#include <arpa/inet.h>

#include <array>
#include <cstdint>
#include <type_traits>
#include <vector>

#include <gtest/gtest.h>

#include "tc8/autosar/someiptp.h"
#include "tc8/someip/protocol.h"
#include "stimulus/method_responder.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/udp_emit.h"
#include "tc8/pollable_service.h"

namespace tc8::stimulus {
namespace {

// Service/method/endpoint the fixtures share. kServiceId/kMethodId match the
// SomeIpRpcMessage defaults (tc8-dut SERVICE-ID-1 / echoUINT8). kServicePort is
// the tester's offered service port — the UDP destination the responder answers.
constexpr std::uint16_t kServiceId = 0xF4E7;
constexpr std::uint16_t kMethodId = 0x0008;
constexpr std::uint16_t kServicePort = 30509;

// Build the on-wire Eth+IPv4+UDP+SOME/IP frame for a DUT-client Method Request
// of `message_type` carrying `payload`, sourced from 172.16.0.9:51000 and
// addressed to the tester service endpoint 172.16.0.1:kServicePort.
std::vector<std::uint8_t> makeRequestFrame(someip::MessageType message_type,
                                           const std::vector<std::uint8_t> &payload) {
    SomeIpRpcMessage t{};
    t.service_id = kServiceId;
    t.method_id = kMethodId;
    t.client_id = 0x1234;
    t.session_id = 0x0005;
    t.message_type = message_type;
    t.payload = payload;
    const std::array<std::uint8_t, 6> dut_mac = {0x02, 0x00, 0x00, 0x00, 0x00, 0x09};
    const std::array<std::uint8_t, 6> tester_mac = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    return buildUdpFromSourceIpFrame(buildMethodRequest(t), ::inet_addr("172.16.0.9"), 51000,
                                     ::inet_addr("172.16.0.1"), kServicePort, dut_mac, tester_mac);
}

// Build the on-wire frame for SOME/IP-TP segment `seg` of a DUT-client Request for
// (kServiceId, kMethodId), Request ID 0x1234/0x0005, carrying `payload` split at
// 16-byte segments (so seg 0 is Offset 0, seg 1 is Offset 16, ...). The Segmenter
// (the TP wire-format SSOT) sets the TP flag on each segment's message type.
std::vector<std::uint8_t> makeTpSegmentFrame(std::size_t seg,
                                             const std::vector<std::uint8_t> &payload) {
    someiptp::MessageHeader hdr{};
    hdr.message_id = (static_cast<std::uint32_t>(kServiceId) << 16) | kMethodId;
    hdr.request_id = (static_cast<std::uint32_t>(0x1234) << 16) | 0x0005;
    hdr.protocol_version = 1;
    hdr.interface_version = 1;
    hdr.message_type = static_cast<std::uint8_t>(someip::MessageType::REQUEST);  // engine ORs the TP flag
    hdr.return_code = 0;
    const auto segments =
        someiptp::Segmenter(/*max_segment_payload=*/16).segment(hdr, payload.data(), payload.size());
    const std::array<std::uint8_t, 6> dut_mac = {0x02, 0x00, 0x00, 0x00, 0x00, 0x09};
    const std::array<std::uint8_t, 6> tester_mac = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    return buildUdpFromSourceIpFrame(segments.at(seg), ::inet_addr("172.16.0.9"), 51000,
                                     ::inet_addr("172.16.0.1"), kServicePort, dut_mac, tester_mac);
}

// The responder is an IPollableService so a case can adopt it onto the runner's
// inline poll loop (no worker thread) — the same seam as ArpResponder.
TEST(MethodResponder, ModelsPollableService) {
    static_assert(std::is_base_of_v<::tc8::IPollableService, MethodResponder>,
                  "MethodResponder must model tc8::IPollableService");
    SUCCEED();
}

// A well-formed Request for the configured (service, method, port) yields the
// reply target (DUT client src ip/port), the echoed Request ID, and the payload.
TEST(MethodResponder, ParsesWellFormedRequest) {
    const std::vector<std::uint8_t> payload = {0xAA, 0xBB, 0xCC};
    const auto frame = makeRequestFrame(someip::MessageType::REQUEST, payload);

    const auto obs = parseMethodRequest(frame.data(), frame.size(), kServiceId, kMethodId, kServicePort);
    ASSERT_TRUE(obs.has_value());
    EXPECT_EQ(obs->src_ip_be, ::inet_addr("172.16.0.9"));  // reply destination
    EXPECT_EQ(obs->src_port, 51000u);
    EXPECT_EQ(obs->service_id, kServiceId);
    EXPECT_EQ(obs->method_id, kMethodId);
    EXPECT_EQ(obs->client_id, 0x1234u);   // SOME/IP Request ID echoed in the reply
    EXPECT_EQ(obs->session_id, 0x0005u);
    EXPECT_EQ(obs->payload, payload);
}

// IPv4 options (IHL > 5) push the UDP header past the fixed 20-byte offset; the
// parser must locate UDP via IHL, not a hardcoded 20. Splice 4 option bytes after
// the IPv4 header and bump IHL 5 -> 6. parseMethodRequest does not read the IP
// total-length / checksum, so leaving those stale is fine for this offset walk.
TEST(MethodResponder, ParsesIpv4WithOptions) {
    const std::vector<std::uint8_t> payload = {0xAA, 0xBB, 0xCC};
    auto frame = makeRequestFrame(someip::MessageType::REQUEST, payload);
    constexpr std::size_t kIpStart = 14;
    frame.insert(frame.begin() + kIpStart + 20, {0x00, 0x00, 0x00, 0x00});       // 4 option bytes
    frame[kIpStart] = static_cast<std::uint8_t>((frame[kIpStart] & 0xF0) | 0x6);  // IHL = 6 (24 bytes)

    const auto obs = parseMethodRequest(frame.data(), frame.size(), kServiceId, kMethodId, kServicePort);
    ASSERT_TRUE(obs.has_value());
    EXPECT_EQ(obs->src_port, 51000u);
    EXPECT_EQ(obs->client_id, 0x1234u);
    EXPECT_EQ(obs->session_id, 0x0005u);
    EXPECT_EQ(obs->payload, payload);  // payload still bounded correctly past the options
}

// A RequestNoReturn (0x01) gets NO reply per PRS_SOMEIP_00701 — the parser
// declines it so the responder never answers a fire-and-forget.
TEST(MethodResponder, RejectsRequestNoReturn) {
    const auto frame = makeRequestFrame(someip::MessageType::REQUEST_NO_RETURN, {0x01});
    EXPECT_FALSE(parseMethodRequest(frame.data(), frame.size(), kServiceId, kMethodId, kServicePort)
                     .has_value());
}

// A Request for a different method (or service, or port) is not ours.
TEST(MethodResponder, RejectsWrongMethodServicePort) {
    const auto frame = makeRequestFrame(someip::MessageType::REQUEST, {0x01});
    EXPECT_FALSE(parseMethodRequest(frame.data(), frame.size(), kServiceId, 0x0009, kServicePort)
                     .has_value());  // wrong method
    EXPECT_FALSE(parseMethodRequest(frame.data(), frame.size(), 0xFFFE, kMethodId, kServicePort)
                     .has_value());  // wrong service
    EXPECT_FALSE(parseMethodRequest(frame.data(), frame.size(), kServiceId, kMethodId, 30490)
                     .has_value());  // wrong destination port
}

// A frame too short to hold Eth+IPv4+UDP+SOME/IP is rejected, never over-read.
TEST(MethodResponder, RejectsTruncated) {
    const auto frame = makeRequestFrame(someip::MessageType::REQUEST, {0x01});
    EXPECT_FALSE(parseMethodRequest(frame.data(), 40, kServiceId, kMethodId, kServicePort).has_value());
    EXPECT_FALSE(parseMethodRequest(nullptr, 0, kServiceId, kMethodId, kServicePort).has_value());
}

// Trailing Ethernet padding (sub-60-byte frames are padded on the wire) must not
// leak into the payload: the extraction is bounded by the UDP Length field.
TEST(MethodResponder, ExcludesEthernetPaddingFromPayload) {
    const std::vector<std::uint8_t> payload = {0xAA, 0xBB, 0xCC};
    auto frame = makeRequestFrame(someip::MessageType::REQUEST, payload);
    frame.insert(frame.end(), {0x00, 0x00, 0x00, 0x00, 0x00, 0x00});  // 6 padding bytes

    const auto obs = parseMethodRequest(frame.data(), frame.size(), kServiceId, kMethodId, kServicePort);
    ASSERT_TRUE(obs.has_value());
    EXPECT_EQ(obs->payload, payload);  // padding excluded, not appended
}

// The first TP segment (Offset 0) of a segmented Request yields the reply target
// and the SAME (client, session) correlation the DUT put on the wire — so the
// tester can answer while the request is still incomplete. `payload` is this first
// segment's chunk only (the first 16 bytes), not the reassembled 48.
TEST(MethodResponder, ParsesFirstTpRequestSegment) {
    std::vector<std::uint8_t> full(48);
    for (std::size_t i = 0; i < full.size(); ++i) full[i] = static_cast<std::uint8_t>(i);
    const auto frame = makeTpSegmentFrame(0, full);

    const auto obs =
        parseFirstTpRequestSegment(frame.data(), frame.size(), kServiceId, kMethodId, kServicePort);
    ASSERT_TRUE(obs.has_value());
    EXPECT_EQ(obs->src_ip_be, ::inet_addr("172.16.0.9"));
    EXPECT_EQ(obs->src_port, 51000u);
    EXPECT_EQ(obs->service_id, kServiceId);
    EXPECT_EQ(obs->method_id, kMethodId);
    EXPECT_EQ(obs->client_id, 0x1234u);
    EXPECT_EQ(obs->session_id, 0x0005u);
    EXPECT_EQ(obs->payload, std::vector<std::uint8_t>(full.begin(), full.begin() + 16));
}

// A LATER segment (Offset != 0) must NOT re-fire the responder — only the first.
TEST(MethodResponder, RejectsLaterTpSegment) {
    std::vector<std::uint8_t> full(48, 0xAB);
    const auto frame = makeTpSegmentFrame(1, full);  // Offset 16
    EXPECT_FALSE(
        parseFirstTpRequestSegment(frame.data(), frame.size(), kServiceId, kMethodId, kServicePort)
            .has_value());
}

// The two parsers are mutually exclusive: a plain Request is not a TP segment, and
// a TP segment is not a plain Request — neither can be mistaken for the other.
TEST(MethodResponder, TpAndNonTpParsersAreMutuallyExclusive) {
    const auto plain = makeRequestFrame(someip::MessageType::REQUEST, {0xAA, 0xBB, 0xCC});
    EXPECT_FALSE(
        parseFirstTpRequestSegment(plain.data(), plain.size(), kServiceId, kMethodId, kServicePort)
            .has_value());

    std::vector<std::uint8_t> full(48, 0x11);
    const auto tp = makeTpSegmentFrame(0, full);
    EXPECT_FALSE(parseMethodRequest(tp.data(), tp.size(), kServiceId, kMethodId, kServicePort).has_value());
}

// A first TP segment for a different method/service/port is not ours.
TEST(MethodResponder, RejectsWrongMethodServicePortTp) {
    std::vector<std::uint8_t> full(48, 0x22);
    const auto frame = makeTpSegmentFrame(0, full);
    EXPECT_FALSE(
        parseFirstTpRequestSegment(frame.data(), frame.size(), kServiceId, 0x000A, kServicePort)
            .has_value());  // wrong method
    EXPECT_FALSE(
        parseFirstTpRequestSegment(frame.data(), frame.size(), 0xFFFE, kMethodId, kServicePort)
            .has_value());  // wrong service
    EXPECT_FALSE(
        parseFirstTpRequestSegment(frame.data(), frame.size(), kServiceId, kMethodId, 30490)
            .has_value());  // wrong destination port
}

// A frame carrying the SOME/IP header but truncated before/within the 4-byte TP
// header is rejected, never over-read.
TEST(MethodResponder, RejectsTruncatedTpHeader) {
    std::vector<std::uint8_t> full(48, 0x33);
    auto frame = makeTpSegmentFrame(0, full);
    // Cut two bytes off the end of the 4-byte TP header (leaving the 16-byte SOME/IP
    // header intact) so the TP-header parse has too few bytes.
    frame.resize(14 + 20 + 8 + 16 + 2);
    EXPECT_FALSE(
        parseFirstTpRequestSegment(frame.data(), frame.size(), kServiceId, kMethodId, kServicePort)
            .has_value());
}

}  // namespace
}  // namespace tc8::stimulus
