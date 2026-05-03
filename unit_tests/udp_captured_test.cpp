#include <array>
#include <cstdint>
#include <vector>

#include <gtest/gtest.h>

#include "sce_integration/udp_captured.h"
#include "stimulus/udp_datagram_builder.h"
#include "tc8/protocol_frames/udp_frame.h"
#include "tc8/upper_tester_protocol.h"

// Coverage for UdpCaptured's `fillUdpCapturedFromFrame` decode of the
// §4.6.5.5 GetReceivedUdp Confirmation trailer. The wire body shape:
//
//   <opcode|0x80:u8> <req_id:u8> <status:u8>
//   <received:u8> [<src_ip:u32 BE> <src_port:u16 BE>
//                  <payload_len:u16 BE> <payload[]>]
//
// Trailer bytes after `received` are populated only when `received == 1`.

namespace tc8 {
namespace {

constexpr std::uint16_t kUtPort       = ut::kPort;          // 30600
constexpr std::uint8_t  kGetRespOpcode =
    static_cast<std::uint8_t>(ut::OpGetReceivedUdp | ut::kResponseBit);

UdpFrame makeBaseFrame(std::uint16_t      src_port,
                        const std::uint8_t *body,
                        std::uint32_t       body_len) {
    UdpFrame f{};
    f.src_ip       = 0x0200A8C0;  // 192.168.0.2 NBO
    f.dst_ip       = 0x0100A8C0;  // 192.168.0.1 NBO
    f.src_port     = src_port;
    f.dst_port     = 20100;
    f.length       = static_cast<std::uint16_t>(8U + body_len);
    f.checksum     = 0x1234;  // arbitrary; not validated here
    f.payload_data = body;
    f.payload_len  = body_len;
    return f;
}

TEST(UdpCapturedTrailerDecode, NoUtResponseWhenSrcPortMismatched) {
    const std::array<std::uint8_t, 4> body{0x81, 0x00, 0x00, 0x01};
    const auto f = makeBaseFrame(/*src_port=*/9999, body.data(), body.size());
    UdpCaptured c{};
    fillUdpCapturedFromFrame(c, f);
    EXPECT_FALSE(c.has_ut_response);
    EXPECT_EQ(c.ut_received, 0U);
}

TEST(UdpCapturedTrailerDecode, NoUtResponseWhenResponseBitClear) {
    // payload[0] = 0x01 (request opcode without 0x80) — must NOT decode
    // as a Confirmation even when src_port matches ut::kPort.
    const std::array<std::uint8_t, 4> body{0x01, 0x00, 0x00, 0x01};
    const auto f = makeBaseFrame(kUtPort, body.data(), body.size());
    UdpCaptured c{};
    fillUdpCapturedFromFrame(c, f);
    EXPECT_FALSE(c.has_ut_response);
}

TEST(UdpCapturedTrailerDecode, UtReceivedZeroLeavesTrailerUnpopulated) {
    // received=0 → no trailer; ut_recv_* must remain zeroed.
    const std::array<std::uint8_t, 4> body{kGetRespOpcode, 0x07, 0x00, 0x00};
    const auto f = makeBaseFrame(kUtPort, body.data(), body.size());
    UdpCaptured c{};
    fillUdpCapturedFromFrame(c, f);
    EXPECT_TRUE(c.has_ut_response);
    EXPECT_EQ(c.ut_opcode, kGetRespOpcode);
    EXPECT_EQ(c.ut_received, 0U);
    EXPECT_EQ(c.ut_recv_src_ip, 0U);
    EXPECT_EQ(c.ut_recv_src_port, 0U);
    EXPECT_EQ(c.ut_recv_payload_len, 0U);
    for (const auto b : c.ut_recv_payload_first16) EXPECT_EQ(b, 0U);
}

TEST(UdpCapturedTrailerDecode, ValidTrailerWithFullPayload) {
    // Body shape: opcode(0x81) + req_id(0x07) + status(0x00) +
    //             received(0x01) +
    //             src_ip BE = 0xC0A80201 (192.168.2.1 wire bytes
    //             C0 A8 02 01 ; harness reads back as NBO uint32 0x0102A8C0) +
    //             src_port BE = 0x4E20 (20000) +
    //             payload_len BE = 0x0008 +
    //             8 B body 0x10..0x80
    std::vector<std::uint8_t> body{
        kGetRespOpcode, 0x07, 0x00, 0x01,
        0xC0, 0xA8, 0x02, 0x01,
        0x4E, 0x20,
        0x00, 0x08,
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80};
    const auto f = makeBaseFrame(kUtPort, body.data(),
                                  static_cast<std::uint32_t>(body.size()));
    UdpCaptured c{};
    fillUdpCapturedFromFrame(c, f);
    EXPECT_TRUE(c.has_ut_response);
    EXPECT_EQ(c.ut_received, 1U);
    EXPECT_EQ(c.ut_recv_src_ip, 0x0102A8C0U);
    EXPECT_EQ(c.ut_recv_src_port, 20000U);
    EXPECT_EQ(c.ut_recv_payload_len, 8U);
    const std::array<std::uint8_t, 8> expected_payload{
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80};
    EXPECT_TRUE(c.ut_recv_payload_equals(expected_payload.data(),
                                          expected_payload.size()));
}

TEST(UdpCapturedTrailerDecode, ShortTrailerLeavesPayloadUnpopulated) {
    // received=1 but body too short (< 12 bytes) — trailer skipped.
    std::vector<std::uint8_t> body{
        kGetRespOpcode, 0x09, 0x00, 0x01, 0xDE, 0xAD};
    const auto f = makeBaseFrame(kUtPort, body.data(),
                                  static_cast<std::uint32_t>(body.size()));
    UdpCaptured c{};
    fillUdpCapturedFromFrame(c, f);
    EXPECT_TRUE(c.has_ut_response);
    EXPECT_EQ(c.ut_received, 1U);
    EXPECT_EQ(c.ut_recv_src_ip, 0U);
    EXPECT_EQ(c.ut_recv_payload_len, 0U);
}

TEST(UdpCapturedTrailerDecode, OversizedPayloadCappedAtFirst16Bytes) {
    // payload_len reports 32 but the harness's first16 array bounds the
    // copy. Confirms the 16-byte cap is enforced and indices [0..15]
    // hold the leading wire bytes.
    std::vector<std::uint8_t> body{
        kGetRespOpcode, 0x01, 0x00, 0x01,
        0x0A, 0x00, 0x00, 0x01,  // src_ip 10.0.0.1 wire bytes
        0x4E, 0x21,                 // src_port 20001
        0x00, 0x20};                // payload_len 32
    for (std::uint8_t i = 0; i < 32; ++i) body.push_back(static_cast<std::uint8_t>(0xA0 + i));
    const auto f = makeBaseFrame(kUtPort, body.data(),
                                  static_cast<std::uint32_t>(body.size()));
    UdpCaptured c{};
    fillUdpCapturedFromFrame(c, f);
    EXPECT_EQ(c.ut_recv_payload_len, 32U);
    for (std::size_t i = 0; i < 16; ++i) {
        EXPECT_EQ(c.ut_recv_payload_first16[i],
                  static_cast<std::uint8_t>(0xA0 + i)) << "i=" << i;
    }
}

// Helper: build a real UDP datagram via the production builder and
// populate a UdpCaptured from it (mirroring what the live pipeline does
// minus the libtins dissection step). The resulting UdpCaptured carries
// the wire's actual computed checksum, so `pseudo_header_checksum_valid`
// must accept it.
UdpCaptured captureFromBuiltDatagram(std::uint32_t src_ip_be,
                                      std::uint32_t dst_ip_be,
                                      std::uint16_t src_port,
                                      std::uint16_t dst_port,
                                      const std::uint8_t *payload,
                                      std::size_t        payload_len) {
    const auto bytes = stimulus::buildUdpDatagram(
        src_ip_be, dst_ip_be, src_port, dst_port, payload, payload_len);
    UdpCaptured c{};
    c.src_ip   = src_ip_be;
    c.dst_ip   = dst_ip_be;
    c.src_port = src_port;
    c.dst_port = dst_port;
    c.length   = static_cast<std::uint16_t>(8U + payload_len);
    c.checksum = static_cast<std::uint16_t>((bytes[6] << 8) | bytes[7]);
    c.payload_snapshot_len = static_cast<std::uint32_t>(payload_len);
    for (std::size_t i = 0; i < payload_len && i < c.payload_snapshot.size();
         ++i) {
        c.payload_snapshot[i] = payload[i];
    }
    return c;
}

TEST(UdpCapturedPseudoHeaderChecksum, EmptyPayloadValidates) {
    // Real builder produces 0xFFFF (post-RFC 768 fold) for this triple;
    // predicate must accept it.
    UdpCaptured c = captureFromBuiltDatagram(
        0x0100A8C0, 0x0200A8C0, /*sp=*/1, /*dp=*/2, nullptr, 0);
    EXPECT_TRUE(c.pseudo_header_checksum_valid());
}

TEST(UdpCapturedPseudoHeaderChecksum, NonTrivialPayloadValidates) {
    const std::array<std::uint8_t, 8> payload{
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80};
    UdpCaptured c = captureFromBuiltDatagram(
        0x010010ACU, 0x020010ACU, 20001, 20000, payload.data(), payload.size());
    EXPECT_TRUE(c.pseudo_header_checksum_valid());
}

TEST(UdpCapturedPseudoHeaderChecksum, OddPayloadValidates) {
    // FIELDS_13 shape — 7 B odd payload, pseudo-header sum requires the
    // implicit zero pad on the trailing byte. Live `udpChecksum` handles
    // this; predicate must accept the result.
    const std::array<std::uint8_t, 7> payload{
        0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7};
    UdpCaptured c = captureFromBuiltDatagram(
        0x010010ACU, 0x020010ACU, 20013, 20000, payload.data(), payload.size());
    EXPECT_TRUE(c.pseudo_header_checksum_valid());
}

TEST(UdpCapturedPseudoHeaderChecksum, BitFlippedChecksumRejected) {
    UdpCaptured c = captureFromBuiltDatagram(
        0x010010ACU, 0x020010ACU, 20001, 20000, nullptr, 0);
    c.checksum ^= 0x0001U;
    EXPECT_FALSE(c.pseudo_header_checksum_valid());
}

TEST(UdpCapturedPseudoHeaderChecksum, MismatchedLengthReturnsFalse) {
    UdpCaptured c{};
    c.length = 100;  // claims 92 B payload
    c.payload_snapshot_len = 0;
    EXPECT_FALSE(c.pseudo_header_checksum_valid());
}

// §4.6.5.5 UDP_USER_INTERFACE_01: response opcode 0x94 carries
// <actual_count:u8> at body[3]. The harness mirror this into
// `ut_create_actual_count` only when ut_opcode matches; cross-talk
// between OpGetReceivedUdp's ut_received slot and OpCreateUdpReceive
// Ports' ut_create_actual_count slot must NOT happen.
TEST(UdpCapturedTrailerDecode, CreateUdpReceivePortsActualCountDecoded) {
    constexpr std::uint8_t kCreateRespOpcode = static_cast<std::uint8_t>(
        ut::OpCreateUdpReceivePorts | ut::kResponseBit);
    const std::array<std::uint8_t, 4> body{kCreateRespOpcode, 0x55, 0x00, 0x0A};
    const auto f = makeBaseFrame(kUtPort, body.data(), body.size());
    UdpCaptured c{};
    fillUdpCapturedFromFrame(c, f);
    EXPECT_TRUE(c.has_ut_response);
    EXPECT_EQ(c.ut_opcode, kCreateRespOpcode);
    EXPECT_EQ(c.ut_status, 0x00U);
    EXPECT_EQ(c.ut_create_actual_count, 0x0AU);
    EXPECT_EQ(c.ut_received, 0U);  // Distinct slot — must stay zero.
}

TEST(UdpCapturedTrailerDecode, CreateUdpReceivePortsShortBodyLeavesCountZero) {
    constexpr std::uint8_t kCreateRespOpcode = static_cast<std::uint8_t>(
        ut::OpCreateUdpReceivePorts | ut::kResponseBit);
    // Only opcode + req_id + status — no actual_count byte. Decoder
    // must keep ut_create_actual_count at default 0.
    const std::array<std::uint8_t, 3> body{kCreateRespOpcode, 0x55, 0x00};
    const auto f = makeBaseFrame(kUtPort, body.data(), body.size());
    UdpCaptured c{};
    fillUdpCapturedFromFrame(c, f);
    EXPECT_TRUE(c.has_ut_response);
    EXPECT_EQ(c.ut_create_actual_count, 0U);
}

}  // namespace
}  // namespace tc8
