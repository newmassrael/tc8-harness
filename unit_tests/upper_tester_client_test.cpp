#include <array>
#include <cstdint>

#include <gtest/gtest.h>

#include "stimulus/upper_tester_client.h"
#include "tc8/upper_tester_protocol.h"

namespace tc8::stimulus {
namespace {

TEST(UpperTesterClient, GetReceivedUdpRequestLayout) {
    // §4.8.5 wire format: <opcode:u8> <req_id:u8> <listen_port:u16>
    // <expected_dst_ip:u32 BE>. Fixed 8 B — pinning the byte layout
    // so a future opcode addition can't silently reshuffle this one.
    const auto req = buildGetReceivedUdpRequest(
        0x42, 20000U, 0xFFFFFFFFU);  // 255.255.255.255 in NBO
    ASSERT_EQ(req.size(), 8u);
    EXPECT_EQ(req[0], static_cast<std::uint8_t>(ut::OpGetReceivedUdp));
    EXPECT_EQ(req[1], 0x42U);
    // listen_port = 20000 = 0x4E20 BE.
    EXPECT_EQ(req[2], 0x4EU);
    EXPECT_EQ(req[3], 0x20U);
    // expected_dst_ip 0xFFFFFFFF — four 0xFF bytes regardless of
    // endianness, but the order must be src_ip-like bytewise.
    EXPECT_EQ(req[4], 0xFFU);
    EXPECT_EQ(req[5], 0xFFU);
    EXPECT_EQ(req[6], 0xFFU);
    EXPECT_EQ(req[7], 0xFFU);
}

TEST(UpperTesterClient, GetReceivedUdpHonoursIpByteOrder) {
    // Request encodes dst_ip in the same byte order the corresponding
    // IPv4 packet used (network byte order stored in a host uint32).
    // 172.16.0.255 NBO = 0xFF0010AC (AC 10 00 FF on wire).
    const auto req = buildGetReceivedUdpRequest(0x00, 0, 0xFF0010ACU);
    ASSERT_EQ(req.size(), 8u);
    EXPECT_EQ(req[4], 0xACU);
    EXPECT_EQ(req[5], 0x10U);
    EXPECT_EQ(req[6], 0x00U);
    EXPECT_EQ(req[7], 0xFFU);
}

TEST(UpperTesterClient, TriggerSendUdpRequestLayout) {
    // Wire format:
    //   <opcode:u8> <req_id:u8> <src_port:u16> <dst_ip:u32>
    //   <dst_port:u16> <payload_len:u16> <payload[]>
    // FRAGMENTS_05 uses src=20001, dst=tester_ip:20000, payload=8 B.
    const std::array<std::uint8_t, 8> payload{0x10, 0x20, 0x30, 0x40,
                                              0x50, 0x60, 0x70, 0x80};
    const auto req = buildTriggerSendUdpRequest(
        0x07, 20001U, 0x010010ACU, 20000U, payload.data(), payload.size());
    ASSERT_EQ(req.size(), 12u + payload.size());
    EXPECT_EQ(req[0], static_cast<std::uint8_t>(ut::OpTriggerSendUdp));
    EXPECT_EQ(req[1], 0x07U);
    EXPECT_EQ(req[2], 0x4EU);
    EXPECT_EQ(req[3], 0x21U);  // 20001 = 0x4E21
    EXPECT_EQ(req[4], 0xACU);
    EXPECT_EQ(req[5], 0x10U);
    EXPECT_EQ(req[6], 0x00U);
    EXPECT_EQ(req[7], 0x01U);  // 172.16.0.1 NBO bytewise
    EXPECT_EQ(req[8], 0x4EU);
    EXPECT_EQ(req[9], 0x20U);  // 20000 = 0x4E20
    EXPECT_EQ(req[10], 0x00U);
    EXPECT_EQ(req[11], payload.size());  // payload_len low byte
    for (std::size_t i = 0; i < payload.size(); ++i) {
        EXPECT_EQ(req[12 + i], payload[i]) << "payload byte " << i;
    }
}

TEST(UpperTesterClient, TriggerSendUdpClampsOversizePayload) {
    // Guard against caller-bug oversize buffers: if payload_len exceeds
    // kMaxPayload, the builder must clamp so the tc8-dut parser sees a
    // bounded body. A silent bloat could push the UT datagram into IPv4
    // fragmentation, which would confound FRAGMENTS_05's own emit-side
    // fragment-absence observation.
    std::vector<std::uint8_t> payload(ut::kMaxPayload + 16, 0xAB);
    const auto req = buildTriggerSendUdpRequest(
        0x00, 0, 0, 0, payload.data(), static_cast<std::uint16_t>(payload.size()));
    ASSERT_EQ(req.size(), 12u + ut::kMaxPayload);
    // payload_len field reflects the clamp, not the oversize input.
    EXPECT_EQ(req[10], static_cast<std::uint8_t>((ut::kMaxPayload >> 8) & 0xFFU));
    EXPECT_EQ(req[11], static_cast<std::uint8_t>(ut::kMaxPayload & 0xFFU));
}

TEST(UpperTesterClient, TriggerSendUdpDefaultOmitsSrcIpTrailer) {
    // src_ip_override default = 0 must produce a byte-identical wire
    // shape to the pre-extension legacy callers (FRAGMENTS_05 / UI_01..06).
    // Same fixture as TriggerSendUdpRequestLayout — a regression here would
    // tell legacy callers their wire shape silently grew.
    const std::array<std::uint8_t, 8> payload{0x10, 0x20, 0x30, 0x40,
                                              0x50, 0x60, 0x70, 0x80};
    const auto legacy = buildTriggerSendUdpRequest(
        0x07, 20001U, 0x010010ACU, 20000U, payload.data(), payload.size());
    const auto explicit_zero = buildTriggerSendUdpRequest(
        0x07, 20001U, 0x010010ACU, 20000U, payload.data(), payload.size(),
        /*src_ip_override_be=*/0U);
    EXPECT_EQ(legacy, explicit_zero);
    EXPECT_EQ(legacy.size(), 12u + payload.size());
}

TEST(UpperTesterClient, TriggerSendUdpAppendsSrcIpTrailerWhenNonZero) {
    // §4.6.5.5 UI_07 wire shape: 4-byte src_ip override appended after
    // the payload. Verifies the trailer is present, in network byte
    // order, and lands at exactly the post-payload offset (legacy
    // bytes 0..11 + payload preserved verbatim).
    const std::array<std::uint8_t, 8> payload{0x10, 0x20, 0x30, 0x40,
                                              0x50, 0x60, 0x70, 0x80};
    const std::uint32_t override_be = 0x050010ACU;  // 172.16.0.5 NBO
    const auto req = buildTriggerSendUdpRequest(
        0x07, 20027U, 0x010010ACU, 20000U, payload.data(), payload.size(),
        override_be);
    ASSERT_EQ(req.size(), 12u + payload.size() + 4u);
    // Legacy header + payload bytes byte-identical to the no-override
    // shape — only the trailer is added.
    EXPECT_EQ(req[0], static_cast<std::uint8_t>(ut::OpTriggerSendUdp));
    EXPECT_EQ(req[1], 0x07U);
    for (std::size_t i = 0; i < payload.size(); ++i) {
        EXPECT_EQ(req[12 + i], payload[i]) << "payload byte " << i;
    }
    // Trailer in NBO: 172.16.0.5 → AC 10 00 05.
    EXPECT_EQ(req[12 + payload.size() + 0], 0xACU);
    EXPECT_EQ(req[12 + payload.size() + 1], 0x10U);
    EXPECT_EQ(req[12 + payload.size() + 2], 0x00U);
    EXPECT_EQ(req[12 + payload.size() + 3], 0x05U);
}

TEST(UpperTesterClient, OpcodeConstantsAreDisjoint) {
    // Request opcodes must have bit 7 clear; response opcodes must have
    // bit 7 set. A tc8-dut parser testing `(byte & 0x80) == 0` to
    // distinguish request from own response relies on this.
    EXPECT_EQ(ut::OpGetReceivedUdp & ut::kResponseBit, 0u);
    EXPECT_EQ(ut::OpTriggerSendUdp & ut::kResponseBit, 0u);
    EXPECT_EQ(ut::OpOpenTcpSocket & ut::kResponseBit, 0u);
    EXPECT_EQ(ut::OpCloseTcpSocket & ut::kResponseBit, 0u);
    EXPECT_EQ(ut::OpQueryTcpEstablished & ut::kResponseBit, 0u);
    EXPECT_EQ(ut::OpSendTcpData & ut::kResponseBit, 0u);
    EXPECT_EQ(ut::kResponseBit, 0x80u);
}

TEST(UpperTesterClient, OpenTcpSocketPassiveRequestLayout) {
    // §4.8.5 wire format: <opcode:u8=0x03> <req_id:u8> <type:u8=0>
    // <local_port:u16>. The leading `type` byte selects passive vs
    // active open; passive carries no remote endpoint trailer.
    const auto req = buildOpenTcpSocketPassiveRequest(0x55, 12345U);
    ASSERT_EQ(req.size(), 5u);
    EXPECT_EQ(req[0], static_cast<std::uint8_t>(ut::OpOpenTcpSocket));
    EXPECT_EQ(req[1], 0x55U);
    EXPECT_EQ(req[2], ut::kSocketTypePassive);
    // 12345 = 0x3039 BE.
    EXPECT_EQ(req[3], 0x30U);
    EXPECT_EQ(req[4], 0x39U);
}

TEST(UpperTesterClient, OpenTcpSocketActiveRequestLayout) {
    // §4.8.5 wire format: <opcode:u8=0x03> <req_id:u8> <type:u8=1>
    // <local_port:u16> <remote_ip:u32 BE> <remote_port:u16>.
    // 11 B fixed — pinning so a future opcode addition cannot reshuffle
    // this one without the test failing first. remote_ip = 172.16.0.1
    // NBO = 0x010010AC; remote_port = 23456 = 0x5BA0 BE.
    const auto req = buildOpenTcpSocketActiveRequest(
        0x66, 49500U, 0x010010ACU, 23456U);
    ASSERT_EQ(req.size(), 11u);
    EXPECT_EQ(req[0], static_cast<std::uint8_t>(ut::OpOpenTcpSocket));
    EXPECT_EQ(req[1], 0x66U);
    EXPECT_EQ(req[2], ut::kSocketTypeActive);
    // local_port = 49500 = 0xC15C BE.
    EXPECT_EQ(req[3], 0xC1U);
    EXPECT_EQ(req[4], 0x5CU);
    // remote_ip 172.16.0.1 NBO bytewise.
    EXPECT_EQ(req[5], 0xACU);
    EXPECT_EQ(req[6], 0x10U);
    EXPECT_EQ(req[7], 0x00U);
    EXPECT_EQ(req[8], 0x01U);
    // remote_port = 23456 = 0x5BA0 BE.
    EXPECT_EQ(req[9], 0x5BU);
    EXPECT_EQ(req[10], 0xA0U);
}

TEST(UpperTesterClient, CloseTcpSocketRequestLayout) {
    const auto req = buildCloseTcpSocketRequest(0x13, 0xAB);
    ASSERT_EQ(req.size(), 3u);
    EXPECT_EQ(req[0], static_cast<std::uint8_t>(ut::OpCloseTcpSocket));
    EXPECT_EQ(req[1], 0x13U);
    EXPECT_EQ(req[2], 0xABU);
}

TEST(UpperTesterClient, QueryTcpEstablishedRequestLayout) {
    const auto req = buildQueryTcpEstablishedRequest(0x77, 0x02);
    ASSERT_EQ(req.size(), 3u);
    EXPECT_EQ(req[0], static_cast<std::uint8_t>(ut::OpQueryTcpEstablished));
    EXPECT_EQ(req[1], 0x77U);
    EXPECT_EQ(req[2], 0x02U);
}

TEST(UpperTesterClient, QueryTcpInfoRequestLayout) {
    // §4.8.5 wire format: <opcode:u8=0x13> <req_id:u8> <socket_id:u8>.
    // Fixed 3 B request — pinning the byte layout so a future opcode
    // addition can't silently reshuffle the §4.8.6.11
    // RETRANSMISSION_TO_03 kernel-info path.
    const auto req = buildQueryTcpInfoRequest(0x33, 0x05);
    ASSERT_EQ(req.size(), 3u);
    EXPECT_EQ(req[0], static_cast<std::uint8_t>(ut::OpQueryTcpInfo));
    EXPECT_EQ(req[0], 0x13U);  // opcode 0x13 lock-in (response = 0x93)
    EXPECT_EQ(req[1], 0x33U);
    EXPECT_EQ(req[2], 0x05U);
}

TEST(UpperTesterClient, SendTcpDataRequestLayout) {
    // §4.8.5 wire format: <opcode:u8=0x06> <req_id:u8> <socket_id:u8>
    // <payload_len:u16> <payload[]>. CHECKSUM_03 sends a small
    // application payload through a tc8-dut connected fd; the spec
    // assertion is on the DUT-emitted segment's checksum, so any
    // non-empty body suffices.
    const std::array<std::uint8_t, 4> payload{0xCA, 0xFE, 0xBA, 0xBE};
    const auto req = buildSendTcpDataRequest(
        0x88, 0x01, payload.data(), payload.size());
    ASSERT_EQ(req.size(), 5u + payload.size());
    EXPECT_EQ(req[0], static_cast<std::uint8_t>(ut::OpSendTcpData));
    EXPECT_EQ(req[1], 0x88U);
    EXPECT_EQ(req[2], 0x01U);
    EXPECT_EQ(req[3], 0x00U);  // payload_len high
    EXPECT_EQ(req[4], 0x04U);  // payload_len low
    for (std::size_t i = 0; i < payload.size(); ++i) {
        EXPECT_EQ(req[5 + i], payload[i]) << "payload byte " << i;
    }
}

TEST(UpperTesterClient, SendTcpDataClampsOversizePayload) {
    // Same clamp behaviour as TriggerSendUdp — caller-bug oversize
    // buffer truncates to kMaxPayload rather than overflowing the
    // tc8-dut parser bound.
    std::vector<std::uint8_t> payload(ut::kMaxPayload + 16, 0x33);
    const auto req = buildSendTcpDataRequest(
        0x00, 0x01, payload.data(), static_cast<std::uint16_t>(payload.size()));
    ASSERT_EQ(req.size(), 5u + ut::kMaxPayload);
    EXPECT_EQ(req[3], static_cast<std::uint8_t>((ut::kMaxPayload >> 8) & 0xFFU));
    EXPECT_EQ(req[4], static_cast<std::uint8_t>(ut::kMaxPayload & 0xFFU));
}

TEST(UpperTesterClient, ReceiveTcpDataRequestLayout) {
    // §4.8.5 wire format: <opcode:u8=0x07> <req_id:u8> <socket_id:u8>
    // <expected_len:u16 BE> <timeout_ms:u16 BE>. Used by
    // §4.8.6.8 TCP_CLOSING_07/_08 to drive DUT-side recv() with a
    // bounded blocking window.
    const auto req = buildReceiveTcpDataRequest(
        /*req_id=*/0x91,
        /*socket_id=*/0x03,
        /*expected_len=*/0x0010,
        /*timeout_ms=*/0x07D0);  // 2000
    ASSERT_EQ(req.size(), 7u);
    EXPECT_EQ(req[0], static_cast<std::uint8_t>(ut::OpReceiveTcpData));
    EXPECT_EQ(req[1], 0x91U);
    EXPECT_EQ(req[2], 0x03U);
    EXPECT_EQ(req[3], 0x00U);  // expected_len high
    EXPECT_EQ(req[4], 0x10U);  // expected_len low
    EXPECT_EQ(req[5], 0x07U);  // timeout_ms high
    EXPECT_EQ(req[6], 0xD0U);  // timeout_ms low
}

TEST(UpperTesterClient, ReceiveTcpDataClampsOversizeExpectedLen) {
    // Same kMaxPayload clamp as the data-bearing requests so a caller-
    // bug oversize expectation doesn't overflow the response buffer
    // budget on the tc8-dut side.
    const auto req = buildReceiveTcpDataRequest(
        0x00, 0x01,
        static_cast<std::uint16_t>(ut::kMaxPayload + 16),
        500);
    ASSERT_EQ(req.size(), 7u);
    EXPECT_EQ(req[3], static_cast<std::uint8_t>((ut::kMaxPayload >> 8) & 0xFFU));
    EXPECT_EQ(req[4], static_cast<std::uint8_t>(ut::kMaxPayload & 0xFFU));
}

TEST(UpperTesterClient, ReceiveTcpDataOobRequestLayout) {
    // §4.8.5 wire format: <opcode:u8=0x0B> <req_id:u8> <socket_id:u8>
    // <expected_len:u16 BE> <timeout_ms:u16 BE>. §4.8.6.14
    // TCP_URGENT_PTR_04 uses this to drive DUT-side recv(MSG_OOB)
    // so the urgent byte is delivered through Linux's OOB queue
    // rather than the normal recv stream.
    const auto req = buildReceiveTcpDataOobRequest(
        /*req_id=*/0xA1,
        /*socket_id=*/0x05,
        /*expected_len=*/0x0001,
        /*timeout_ms=*/0x07D0);  // 2000
    ASSERT_EQ(req.size(), 7u);
    EXPECT_EQ(req[0], static_cast<std::uint8_t>(ut::OpReceiveTcpDataOob));
    EXPECT_EQ(req[1], 0xA1U);
    EXPECT_EQ(req[2], 0x05U);
    EXPECT_EQ(req[3], 0x00U);  // expected_len high
    EXPECT_EQ(req[4], 0x01U);  // expected_len low
    EXPECT_EQ(req[5], 0x07U);  // timeout_ms high
    EXPECT_EQ(req[6], 0xD0U);  // timeout_ms low
    // 0x0B must keep bit 7 clear so the future response opcode
    // 0x8B remains disjoint from the request opcode.
    EXPECT_EQ(ut::OpReceiveTcpDataOob & ut::kResponseBit, 0u);
}

TEST(UpperTesterClient, ReceiveTcpDataOobClampsOversizeExpectedLen) {
    const auto req = buildReceiveTcpDataOobRequest(
        0x00, 0x01,
        static_cast<std::uint16_t>(ut::kMaxPayload + 16),
        500);
    ASSERT_EQ(req.size(), 7u);
    EXPECT_EQ(req[3], static_cast<std::uint8_t>((ut::kMaxPayload >> 8) & 0xFFU));
    EXPECT_EQ(req[4], static_cast<std::uint8_t>(ut::kMaxPayload & 0xFFU));
}

TEST(UpperTesterClient, ShutdownTcpSocketWrRequestLayout) {
    // §4.8.5 wire format: <opcode:u8=0x08> <req_id:u8> <socket_id:u8>.
    // §4.8.6.8 TCP_CLOSING_07/_08 use this for "CLOSE-as-half-shutdown"
    // semantics that keep the recv side open.
    const auto req = buildShutdownTcpSocketWrRequest(0x42, 0x01);
    ASSERT_EQ(req.size(), 3u);
    EXPECT_EQ(req[0], static_cast<std::uint8_t>(ut::OpShutdownTcpSocketWr));
    EXPECT_EQ(req[1], 0x42U);
    EXPECT_EQ(req[2], 0x01U);
}

TEST(UpperTesterClient, AbortTcpSocketRequestLayout) {
    // §4.8.5 wire format: <opcode:u8=0x09> <req_id:u8> <socket_id:u8>.
    // §4.8.6.5 TCP_CALL_ABORT_02/_03 use this to drive the spec's
    // ABORT primitive (SO_LINGER {1,0} + close → RST egress).
    const auto req = buildAbortTcpSocketRequest(0x99, 0x07);
    ASSERT_EQ(req.size(), 3u);
    EXPECT_EQ(req[0], static_cast<std::uint8_t>(ut::OpAbortTcpSocket));
    EXPECT_EQ(req[1], 0x99U);
    EXPECT_EQ(req[2], 0x07U);
    // 0x09 must keep bit 7 clear so a future response opcode 0x89
    // remains disjoint from the request opcode.
    EXPECT_EQ(ut::OpAbortTcpSocket & ut::kResponseBit, 0u);
}

TEST(UpperTesterClient, CreateUdpReceivePortsRequestLayout) {
    // §4.8.5 wire format: <opcode:u8=0x14> <req_id:u8> <count:u8>.
    // §4.6.5.5 UDP_USER_INTERFACE_01 drives this with count=10; the
    // tc8-dut responds <opcode|0x80=0x94> <req_id> <status> <actual:u8>.
    // Pinning the 3 B request layout so a future opcode addition cannot
    // silently reshuffle the dynamic-receive-port verification path.
    const auto req = buildCreateUdpReceivePortsRequest(0x55, 10U);
    ASSERT_EQ(req.size(), 3u);
    EXPECT_EQ(req[0], static_cast<std::uint8_t>(ut::OpCreateUdpReceivePorts));
    EXPECT_EQ(req[0], 0x14U);  // opcode 0x14 lock-in (response = 0x94)
    EXPECT_EQ(req[1], 0x55U);
    EXPECT_EQ(req[2], 10U);
    // 0x14 must keep bit 7 clear so a future response opcode 0x94
    // remains disjoint from the request opcode.
    EXPECT_EQ(ut::OpCreateUdpReceivePorts & ut::kResponseBit, 0u);
}

TEST(UpperTesterClient, SendTcpDataPatternRequestLayout) {
    // §4.8.5 wire format: <opcode:u8=0x0A> <req_id:u8> <socket_id:u8>
    // <pattern:u8> <total_len:u16 BE>. §4.8.6.9 MSS_OPTIONS_06/_09/_10
    // use this to drive bulk DUT-side sends (1500+ B) without bloating
    // the UT request datagram past MTU.
    const auto req = buildSendTcpDataPatternRequest(
        /*req_id=*/0xAA,
        /*socket_id=*/0x01,
        /*pattern=*/0x5AU,
        /*total_len=*/0x07D0U);  // 2000
    ASSERT_EQ(req.size(), 6u);
    EXPECT_EQ(req[0], static_cast<std::uint8_t>(ut::OpSendTcpDataPattern));
    EXPECT_EQ(req[1], 0xAAU);
    EXPECT_EQ(req[2], 0x01U);
    EXPECT_EQ(req[3], 0x5AU);
    EXPECT_EQ(req[4], 0x07U);
    EXPECT_EQ(req[5], 0xD0U);
    // 0x0A must keep bit 7 clear so the future response opcode 0x8A
    // remains disjoint from the request opcode.
    EXPECT_EQ(ut::OpSendTcpDataPattern & ut::kResponseBit, 0u);
}


TEST(UpperTesterClient, PingRequestLayout) {
    // Wire format: <opcode:u8=0x15> <req_id:u8> — parameterless probe.
    // smoke-test.sh topology preflights depend on this exact 2 B shape
    // via the `ut-ping` CLI subcommand; the response carries
    // <max_opcode:u8> after the status byte so subset DUT firmwares
    // are detectable.
    const auto req = buildPingRequest(0x42);
    ASSERT_EQ(req.size(), 2u);
    EXPECT_EQ(req[0], static_cast<std::uint8_t>(ut::OpPing));
    EXPECT_EQ(req[0], 0x15U);  // opcode 0x15 lock-in (response = 0x95)
    EXPECT_EQ(req[1], 0x42U);
    EXPECT_EQ(ut::OpPing & ut::kResponseBit, 0u);
    // kMaxProtocolOpcode must track the highest enum value — a new
    // opcode without the bump would size the capability bitmap too
    // small for the new bit.
    EXPECT_EQ(ut::kMaxProtocolOpcode,
              static_cast<std::uint8_t>(ut::OpConditionArpCache));
}


TEST(UpperTesterClient, QueryCapabilitiesRequestLayout) {
    // Wire format: <opcode:u8=0x16> <req_id:u8> — parameterless probe
    // mirroring OpPing. Response carries <bitmap_len:u8> <bitmap[]>.
    const auto req = buildQueryCapabilitiesRequest(0x17);
    ASSERT_EQ(req.size(), 2u);
    EXPECT_EQ(req[0], static_cast<std::uint8_t>(ut::OpQueryCapabilities));
    EXPECT_EQ(req[0], 0x16U);  // opcode lock-in (response = 0x96)
    EXPECT_EQ(req[1], 0x17U);
    EXPECT_EQ(ut::OpQueryCapabilities & ut::kResponseBit, 0u);
}


TEST(UpperTesterClient, ConditionArpCacheRequestLayout) {
    // Wire format: <opcode:u8=0x17> <req_id:u8> <action:u8>
    // <param:u16 BE>. ARP_48/49 AgeBySeconds with the lwIP fixture's
    // 300 s ARP_MAXAGE = 0x012C.
    const auto req = buildConditionArpCacheRequest(
        0x05, ut::kArpConditionAgeBySeconds, 300U);
    ASSERT_EQ(req.size(), 5u);
    EXPECT_EQ(req[0], static_cast<std::uint8_t>(ut::OpConditionArpCache));
    EXPECT_EQ(req[0], 0x17U);  // opcode lock-in (response = 0x97)
    EXPECT_EQ(req[1], 0x05U);
    EXPECT_EQ(req[2], ut::kArpConditionAgeBySeconds);
    EXPECT_EQ(req[3], 0x01U);
    EXPECT_EQ(req[4], 0x2CU);
    EXPECT_EQ(ut::OpConditionArpCache & ut::kResponseBit, 0u);
}


TEST(UpperTesterClient, CapabilityBitmapRoundTrip) {
    // The packing SSOT: makeCapabilityBitmap sets exactly the listed
    // opcodes' bits; capabilityBitSet reads them back; everything
    // unlisted reads as unimplemented. The sparse lwIP-shaped set
    // (contiguous low block + 0x13+ block) is the motivating case.
    constexpr std::uint8_t kSet[] = {
        ut::OpGetReceivedUdp,    ut::OpReceiveTcpDataOob,
        ut::OpQueryTcpInfo,      ut::OpPing,
        ut::OpQueryCapabilities, ut::OpConditionArpCache,
    };
    constexpr auto bitmap = ut::makeCapabilityBitmap(kSet);
    ASSERT_EQ(bitmap.size(), ut::kCapabilityBitmapBytes);
    for (unsigned op = 0x00; op <= ut::kMaxProtocolOpcode; ++op) {
        bool expected = false;
        for (const std::uint8_t s : kSet) {
            expected = expected || (s == op);
        }
        EXPECT_EQ(ut::capabilityBitSet(bitmap.data(), bitmap.size(),
                                       static_cast<std::uint8_t>(op)),
                  expected)
            << "opcode 0x" << std::hex << op;
    }
    // A truncated wire bitmap (older DUT, shorter response) reads the
    // missing high bytes as all-unimplemented, never out-of-bounds.
    EXPECT_FALSE(ut::capabilityBitSet(bitmap.data(), 2u,
                                      ut::OpConditionArpCache));
    EXPECT_TRUE(ut::capabilityBitSet(bitmap.data(), 2u,
                                     ut::OpReceiveTcpDataOob));
}


}  // namespace
}  // namespace tc8::stimulus
