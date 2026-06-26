// Pins SD options-array decoding inside `parseSdOptionsInto`. Builds
// synthetic SOME/IP-SD payloads matching SWS_SD §7.3 Table 11 wire layout
// (16-byte entries; per-option tuple of [Length(2B BE), Type(1B), tail])
// and verifies the decoded `sd_options[]` and per-type counts. These
// tests are the spec-correctness gate for §5.1.5.5 SOMEIPSRV_OPTIONS
// case guards.

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

#include "autosar/someiptp.h"
#include "sce_integration/someip_captured.h"

namespace {

// Big-endian appenders — keeps test fixtures readable as a sequence of
// labelled field writes rather than nested shift/mask expressions.
void appendBe16(std::vector<std::uint8_t> &buf, std::uint16_t v) {
    buf.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>(v & 0xFF));
}

void appendBe32(std::vector<std::uint8_t> &buf, std::uint32_t v) {
    buf.push_back(static_cast<std::uint8_t>((v >> 24) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>(v & 0xFF));
}

// Build a single IPv4 Endpoint Option (Type=0x04 or 0x14) following the
// 12-byte SWS_SD §7.3 Table 11 wire layout. Length field is the spec-
// mandated 0x0009 (covers Reserved + Address + Reserved + L4 + Port).
// `wire_ipv4` is laid down on the wire MSB-first (so 0xAC100002 emits
// `AC 10 00 02` for 172.16.0.2) — the parser stores the same wire bytes
// back into a uint32 via memcpy, yielding network byte order.
void appendIpv4EndpointOption(std::vector<std::uint8_t> &buf, std::uint8_t type, std::uint32_t wire_ipv4,
                              std::uint8_t l4, std::uint16_t port) {
    appendBe16(buf, 0x0009);
    buf.push_back(type);
    buf.push_back(0x00);  // first reserved
    appendBe32(buf, wire_ipv4);
    buf.push_back(0x00);  // second reserved
    buf.push_back(l4);
    appendBe16(buf, port);
}

// Convert a wire-MSB-first IPv4 uint32 (e.g. 0xAC100002 for 172.16.0.2)
// into the same value an inet_pton-driven `parseIpv4Dotted` would store
// (network byte order — i.e. `addr.s_addr`). This matches what
// `parseSdOptionsInto` writes into `sd_options[].ipv4`.
std::uint32_t toNetworkOrder(std::uint32_t wire_be) {
    std::array<std::uint8_t, 4> bytes{
        static_cast<std::uint8_t>((wire_be >> 24) & 0xFF),
        static_cast<std::uint8_t>((wire_be >> 16) & 0xFF),
        static_cast<std::uint8_t>((wire_be >> 8) & 0xFF),
        static_cast<std::uint8_t>(wire_be & 0xFF),
    };
    std::uint32_t out = 0;
    std::memcpy(&out, bytes.data(), 4);
    return out;
}

// Build a synthetic SD payload with the given entries and options blocks.
// Layout: Flags(1) + Reserved(3) + LengthOfEntriesArray(4) + Entries +
// LengthOfOptionsArray(4) + Options.
std::vector<std::uint8_t> buildSdPayload(const std::vector<std::uint8_t> &entries,
                                          const std::vector<std::uint8_t> &options) {
    std::vector<std::uint8_t> buf;
    buf.push_back(0xC0);  // Flags: Reboot=1, Unicast=1
    buf.push_back(0x00);
    buf.push_back(0x00);
    buf.push_back(0x00);
    appendBe32(buf, static_cast<std::uint32_t>(entries.size()));
    buf.insert(buf.end(), entries.begin(), entries.end());
    appendBe32(buf, static_cast<std::uint32_t>(options.size()));
    buf.insert(buf.end(), options.begin(), options.end());
    return buf;
}

// 16-byte FindService entry (Type=0x00). Padding values aren't relevant
// for options decoding — we only need the entries-array length to be
// consistent so parseSdHeaderInto reaches the options block.
std::vector<std::uint8_t> findServiceEntry() {
    return std::vector<std::uint8_t>(16, 0x00);
}

}  // namespace

TEST(SomeIpCapturedSdOptions, EmptyOptionsArrayKeepsCountsZero) {
    const auto payload = buildSdPayload(findServiceEntry(), {});
    tc8::SomeIpCaptured c;
    tc8::parseSdHeaderInto(c, payload.data(), payload.size());
    tc8::parseSdOptionsInto(c, payload.data(), payload.size());

    EXPECT_EQ(c.sd_options_len, 0u);
    EXPECT_EQ(c.sd_option_count, 0u);
    EXPECT_EQ(c.sd_ipv4_endpoint_count, 0u);
    EXPECT_EQ(c.sd_ipv4_multicast_count, 0u);
}

TEST(SomeIpCapturedSdOptions, SingleIpv4EndpointOptionDecodesAllFields) {
    std::vector<std::uint8_t> options;
    appendIpv4EndpointOption(options, /*type=*/0x04, /*wire_ipv4=*/0xAC100002U, /*l4=*/0x11,
                             /*port=*/0x7726);  // 30502
    const auto payload = buildSdPayload(findServiceEntry(), options);

    tc8::SomeIpCaptured c;
    tc8::parseSdHeaderInto(c, payload.data(), payload.size());
    tc8::parseSdOptionsInto(c, payload.data(), payload.size());

    ASSERT_EQ(c.sd_option_count, 1u);
    EXPECT_EQ(c.sd_ipv4_endpoint_count, 1u);
    EXPECT_EQ(c.sd_ipv4_multicast_count, 0u);

    const auto &o = c.sd_options[0];
    EXPECT_EQ(o.length, 0x0009u);
    EXPECT_EQ(o.type, 0x04u);
    EXPECT_EQ(o.reserved1, 0x00u);
    EXPECT_EQ(o.ipv4, toNetworkOrder(0xAC100002u));
    EXPECT_EQ(o.reserved2, 0x00u);
    EXPECT_EQ(o.l4_proto, 0x11u);
    EXPECT_EQ(o.port, 30502u);
}

TEST(SomeIpCapturedSdOptions, TwoIpv4EndpointOptionsBothDecoded) {
    // Mirrors the actual vsomeip OfferService for service 0xF4E7 — emits
    // one UDP-flavoured IPv4 Endpoint Option (l4=0x11, port=30502) and
    // one TCP-flavoured (l4=0x06, port=30501). OPTIONS_06/07/15 cases
    // depend on both being parsed and indexable independently.
    std::vector<std::uint8_t> options;
    appendIpv4EndpointOption(options, 0x04, 0xAC100002U, 0x11, 30502);
    appendIpv4EndpointOption(options, 0x04, 0xAC100002U, 0x06, 30501);
    const auto payload = buildSdPayload(findServiceEntry(), options);

    tc8::SomeIpCaptured c;
    tc8::parseSdHeaderInto(c, payload.data(), payload.size());
    tc8::parseSdOptionsInto(c, payload.data(), payload.size());

    ASSERT_EQ(c.sd_option_count, 2u);
    EXPECT_EQ(c.sd_ipv4_endpoint_count, 2u);
    EXPECT_EQ(c.sd_options[0].l4_proto, 0x11u);
    EXPECT_EQ(c.sd_options[0].port, 30502u);
    EXPECT_EQ(c.sd_options[1].l4_proto, 0x06u);
    EXPECT_EQ(c.sd_options[1].port, 30501u);

    EXPECT_TRUE(c.sd_has_option_with_l4(0x04, 0x11));
    EXPECT_TRUE(c.sd_has_option_with_l4(0x04, 0x06));
    EXPECT_FALSE(c.sd_has_option_with_l4(0x14, 0x11));
}

TEST(SomeIpCapturedSdOptions, FirstOptionByL4ReturnsMatchingFields) {
    std::vector<std::uint8_t> options;
    appendIpv4EndpointOption(options, 0x04, 0xAC100002U, 0x11, 30502);
    appendIpv4EndpointOption(options, 0x04, 0xAC100002U, 0x06, 30501);
    const auto payload = buildSdPayload(findServiceEntry(), options);

    tc8::SomeIpCaptured c;
    tc8::parseSdHeaderInto(c, payload.data(), payload.size());
    tc8::parseSdOptionsInto(c, payload.data(), payload.size());

    const auto &udp = c.sd_first_option_with_l4(0x04, 0x11);
    EXPECT_EQ(udp.port, 30502u);
    const auto &tcp = c.sd_first_option_with_l4(0x04, 0x06);
    EXPECT_EQ(tcp.port, 30501u);

    // Empty fallback for an absent (type, l4) pair — guards that lift
    // sd_first_option_with_l4 into a guard expression must tolerate this.
    const auto &absent = c.sd_first_option_with_l4(0x14, 0x11);
    EXPECT_EQ(absent.length, 0u);
    EXPECT_EQ(absent.type, 0u);
}

TEST(SomeIpCapturedSdOptions, Ipv4MulticastOptionDecodesIntoMulticastCount) {
    std::vector<std::uint8_t> options;
    appendIpv4EndpointOption(options, /*type=*/0x14, /*ipv4=*/0xE0F4E0F5U, /*l4=*/0x11,
                             /*port=*/30509);
    const auto payload = buildSdPayload(findServiceEntry(), options);

    tc8::SomeIpCaptured c;
    tc8::parseSdHeaderInto(c, payload.data(), payload.size());
    tc8::parseSdOptionsInto(c, payload.data(), payload.size());

    ASSERT_EQ(c.sd_option_count, 1u);
    EXPECT_EQ(c.sd_ipv4_endpoint_count, 0u);
    EXPECT_EQ(c.sd_ipv4_multicast_count, 1u);
    EXPECT_EQ(c.sd_options[0].type, 0x14u);
    EXPECT_EQ(c.sd_options[0].ipv4, toNetworkOrder(0xE0F4E0F5u));
}

TEST(SomeIpCapturedSdOptions, TruncatedOptionTailStopsParseEarly) {
    // Declared options length is 12 (one full option) but we only supply
    // 8 bytes — parser must stop at the boundary and leave sd_option_count
    // at 0 rather than walking past the buffer.
    std::vector<std::uint8_t> options;
    appendBe16(options, 0x0009);  // Length
    options.push_back(0x04);      // Type
    // Truncated at 5 more bytes (would need 9 to complete).
    options.push_back(0x00);
    options.push_back(0xAC);
    options.push_back(0x10);
    options.push_back(0x00);
    options.push_back(0x02);

    auto payload = buildSdPayload(findServiceEntry(), options);
    // Lie in the options-length field: claim a full 12-byte option but
    // only supply 8 bytes after the length header.
    const std::size_t entries_start = 8;
    const std::size_t opts_len_offset = entries_start + 16;
    payload[opts_len_offset + 0] = 0x00;
    payload[opts_len_offset + 1] = 0x00;
    payload[opts_len_offset + 2] = 0x00;
    payload[opts_len_offset + 3] = 0x0C;  // 12

    tc8::SomeIpCaptured c;
    tc8::parseSdHeaderInto(c, payload.data(), payload.size());
    tc8::parseSdOptionsInto(c, payload.data(), payload.size());

    EXPECT_EQ(c.sd_options_len, 12u);
    EXPECT_EQ(c.sd_option_count, 0u);
}

// SOME/IP-TP capture: with the TP-Flag set, fillSomeIpCapturedFromFrame surfaces the
// segment's offset / More-Segments / payload length (decoded via the shared
// someiptp::parseTpHeader). Non-TP frames leave the fields default.
TEST(SomeIpCapturedTp, ParsesTpHeaderWhenFlagSet) {
    // TP word: offset 16 (0x10) | More-Segments (bit 0) = 0x00000011, then 16 segment
    // bytes -> payload_len 20, tp_segment_len 16.
    std::vector<std::uint8_t> payload = {0x00, 0x00, 0x00, 0x11};
    payload.resize(4 + 16, 0xAB);

    tc8::SomeIpFrame f;
    f.service_id = 0x1234;  // not SD (0xFFFF)
    f.message_type = static_cast<std::uint8_t>(0x80 | tc8::someiptp::kMessageTypeTpFlag);
    f.payload_data = payload.data();
    f.payload_len = static_cast<std::uint32_t>(payload.size());

    tc8::SomeIpCaptured c;
    tc8::fillSomeIpCapturedFromFrame(c, f);

    EXPECT_TRUE(c.is_tp);
    EXPECT_EQ(c.tp_offset, 16u);
    EXPECT_TRUE(c.tp_more_segments);
    EXPECT_EQ(c.tp_segment_len, 16u);
}

TEST(SomeIpCapturedTp, NonTpFrameLeavesFieldsDefault) {
    std::vector<std::uint8_t> payload(8, 0x00);
    tc8::SomeIpFrame f;
    f.service_id = 0x1234;
    f.message_type = 0x80;  // Response, no TP-Flag
    f.payload_data = payload.data();
    f.payload_len = static_cast<std::uint32_t>(payload.size());

    tc8::SomeIpCaptured c;
    tc8::fillSomeIpCapturedFromFrame(c, f);

    EXPECT_FALSE(c.is_tp);
    EXPECT_EQ(c.tp_offset, 0u);
    EXPECT_FALSE(c.tp_more_segments);
    EXPECT_EQ(c.tp_segment_len, 0u);
}
