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
#include <string>
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

// Build a Configuration Option (type 0x01) wire block: Length(2B) + Type(0x01) +
// Reserved(1B) + the DNS TXT-like config string ([len][item bytes]... terminated by a
// zero-length byte). `items` are the "key=value" / "key=" / "key" strings, in order.
std::vector<std::uint8_t> buildConfigOption(const std::vector<std::string> &items) {
    std::vector<std::uint8_t> cs;  // the config string (option body after the Reserved byte)
    for (const std::string &it : items) {
        cs.push_back(static_cast<std::uint8_t>(it.size()));
        cs.insert(cs.end(), it.begin(), it.end());
    }
    cs.push_back(0x00);  // zero-length terminator
    std::vector<std::uint8_t> opt;
    appendBe16(opt, static_cast<std::uint16_t>(1 + cs.size()));  // Length = Reserved + config string
    opt.push_back(0x01);  // Type = Configuration Option
    opt.push_back(0x00);  // Reserved
    opt.insert(opt.end(), cs.begin(), cs.end());
    return opt;
}

// Wrap a caller-supplied (possibly malformed) config string in the Configuration
// Option header (Length + Type 0x01 + Reserved) — for negative/bounds tests.
std::vector<std::uint8_t> buildConfigOptionRaw(const std::vector<std::uint8_t> &config_string) {
    std::vector<std::uint8_t> opt;
    appendBe16(opt, static_cast<std::uint16_t>(1 + config_string.size()));  // Length = Reserved + cs
    opt.push_back(0x01);
    opt.push_back(0x00);
    opt.insert(opt.end(), config_string.begin(), config_string.end());
    return opt;
}

}  // namespace

TEST(SomeIpCapturedSdOptions, EmptyOptionsArrayKeepsCountsZero) {
    const auto payload = buildSdPayload(findServiceEntry(), {});
    tc8::SomeIpCaptured c;
    tc8::parseSdInto(c, payload.data(), payload.size());

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
    tc8::parseSdInto(c, payload.data(), payload.size());

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
    tc8::parseSdInto(c, payload.data(), payload.size());

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
    tc8::parseSdInto(c, payload.data(), payload.size());

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
    tc8::parseSdInto(c, payload.data(), payload.size());

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
    tc8::parseSdInto(c, payload.data(), payload.size());

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

// SOME/IP-SD Configuration Option (type 0x01): parseSdOptionsInto decodes the DNS
// TXT-like length-prefixed "key[=value]" items the option body carries.
TEST(SomeIpCapturedConfigOption, ParsesItemsAndKeyValues) {
    const auto opt = buildConfigOption({"key=value", "k2"});
    const auto payload = buildSdPayload(findServiceEntry(), opt);

    tc8::SomeIpCaptured c;
    tc8::parseSdInto(c, payload.data(), payload.size());

    ASSERT_EQ(c.sd_option_count, 1u);
    EXPECT_EQ(c.sd_options[0].type, tc8::sd_option_type::kConfiguration);
    ASSERT_EQ(c.sd_config_item_count, 2u);
    EXPECT_EQ(c.sd_config_items[0].len, 9u);  // "key=value" = 3 + 1 + 5
    EXPECT_EQ(c.sd_config_items[1].len, 2u);  // "k2"
    EXPECT_TRUE(c.sd_config_has_key("key"));
    EXPECT_EQ(c.sd_config_value_of("key"), "value");
    EXPECT_TRUE(c.sd_config_has_key("k2"));     // key present with no value
    EXPECT_EQ(c.sd_config_value_of("k2"), "");  // no '=' -> empty value
    EXPECT_FALSE(c.sd_config_has_key("absent"));
}

TEST(SomeIpCapturedConfigOption, EmptyValueAndKeyOnly) {
    const auto opt = buildConfigOption({"key=", "lone"});  // empty value; no '='
    const auto payload = buildSdPayload(findServiceEntry(), opt);

    tc8::SomeIpCaptured c;
    tc8::parseSdInto(c, payload.data(), payload.size());

    ASSERT_EQ(c.sd_config_item_count, 2u);
    EXPECT_TRUE(c.sd_config_has_key("key"));
    EXPECT_EQ(c.sd_config_value_of("key"), "");  // "key=" -> present, empty value
    EXPECT_TRUE(c.sd_config_has_key("lone"));
    EXPECT_EQ(c.sd_config_value_of("lone"), "");  // "lone" -> no value
}

// An item longer than the capture cap records its true on-wire length but stores only
// the capped bytes (captured < len) — no over-read, and the truncation is detectable.
TEST(SomeIpCapturedConfigOption, ItemLongerThanCapTruncatesContent) {
    const std::string big(100, 'x');  // > kMaxSdConfigItemLen (64)
    const auto payload = buildSdPayload(findServiceEntry(), buildConfigOption({big}));

    tc8::SomeIpCaptured c;
    tc8::parseSdInto(c, payload.data(), payload.size());

    ASSERT_EQ(c.sd_config_item_count, 1u);
    EXPECT_EQ(c.sd_config_items[0].len, 100u);                          // true on-wire length
    EXPECT_EQ(c.sd_config_items[0].captured, tc8::kMaxSdConfigItemLen);  // stored bytes capped
}

// More items than the array holds: parsing stops at the cap, no overflow.
TEST(SomeIpCapturedConfigOption, CapsAtMaxItems) {
    std::vector<std::string> items;
    for (int i = 0; i < 12; ++i) {  // > kMaxSdConfigItems (8)
        items.push_back("k" + std::to_string(i));
    }
    const auto payload = buildSdPayload(findServiceEntry(), buildConfigOption(items));

    tc8::SomeIpCaptured c;
    tc8::parseSdInto(c, payload.data(), payload.size());

    EXPECT_EQ(c.sd_config_item_count, tc8::SomeIpCaptured::kMaxSdConfigItems);
}

// Two Configuration Options in one message: only the first is parsed into the items.
TEST(SomeIpCapturedConfigOption, OnlyFirstConfigOptionParsed) {
    auto options = buildConfigOption({"a=1"});
    const auto second = buildConfigOption({"b=2"});
    options.insert(options.end(), second.begin(), second.end());
    const auto payload = buildSdPayload(findServiceEntry(), options);

    tc8::SomeIpCaptured c;
    tc8::parseSdInto(c, payload.data(), payload.size());

    EXPECT_EQ(c.sd_option_count, 2u);          // both options seen
    ASSERT_EQ(c.sd_config_item_count, 1u);     // only the first parsed into items
    EXPECT_TRUE(c.sd_config_has_key("a"));
    EXPECT_FALSE(c.sd_config_has_key("b"));
}

// A length byte claiming more bytes than the option body holds: the truncated item is
// dropped, no over-read past the option.
TEST(SomeIpCapturedConfigOption, TruncatedItemDropped) {
    // config string: length byte 9, but only "abc" (3 bytes) follow.
    const auto payload =
        buildSdPayload(findServiceEntry(), buildConfigOptionRaw({0x09, 'a', 'b', 'c'}));

    tc8::SomeIpCaptured c;
    tc8::parseSdInto(c, payload.data(), payload.size());

    EXPECT_EQ(c.sd_config_item_count, 0u);
}

// The capture context is reused across frames: a TP frame then a non-TP frame on the
// same context must clear the TP fields, so is_tp never reads stale-true.
TEST(SomeIpCapturedTp, StaleStateClearedOnNonTpFrame) {
    tc8::SomeIpCaptured c;

    std::vector<std::uint8_t> tp_payload = {0x00, 0x00, 0x00, 0x11};  // offset 16, more=1
    tp_payload.resize(4 + 16, 0xAB);
    tc8::SomeIpFrame tp{};
    tp.service_id = 0x1234;
    tp.message_type = static_cast<std::uint8_t>(0x80 | tc8::someiptp::kMessageTypeTpFlag);
    tp.payload_data = tp_payload.data();
    tp.payload_len = static_cast<std::uint32_t>(tp_payload.size());
    tc8::fillSomeIpCapturedFromFrame(c, tp);
    ASSERT_TRUE(c.is_tp);

    std::vector<std::uint8_t> plain(8, 0x00);
    tc8::SomeIpFrame nf{};
    nf.service_id = 0x1234;
    nf.message_type = 0x80;  // no TP-Flag
    nf.payload_data = plain.data();
    nf.payload_len = static_cast<std::uint32_t>(plain.size());
    tc8::fillSomeIpCapturedFromFrame(c, nf);

    EXPECT_FALSE(c.is_tp);
    EXPECT_EQ(c.tp_offset, 0u);
    EXPECT_FALSE(c.tp_more_segments);
    EXPECT_EQ(c.tp_segment_len, 0u);
}

// SOMEIPCLT: the DUT acts as client and capture must surface its Method Request
// as a DUT-as-source frame — full header + the src_ip/src_port reply target that
// feeds emitMethodReply. Capture is direction-agnostic, so the same
// fillSomeIpCapturedFromFrame path that records DUT responses records DUT
// requests; is_method_request_for is the canonical client-role recognizer.
TEST(SomeIpCapturedClientRequest, SurfacesHeaderAndReplyTarget) {
    const std::uint8_t payload[] = {0x42};
    tc8::SomeIpFrame f{};
    f.src_ip = 0xAC100002u;  // DUT client endpoint — the reply target.
    f.src_port = 0xC123u;
    f.dst_ip = 0xAC100001u;  // tester (server).
    f.dst_port = 30509u;     // tester's offered service port.
    f.service_id = 0xF4E7u;
    f.method_id = 0x0008u;
    f.client_id = 0x1234u;
    f.session_id = 0x0007u;
    f.message_type = static_cast<std::uint8_t>(tc8::someip::MessageType::REQUEST);
    f.payload_data = payload;
    f.payload_len = sizeof(payload);

    tc8::SomeIpCaptured c{};
    tc8::fillSomeIpCapturedFromFrame(c, f);

    // The reply target is the captured request's source endpoint.
    EXPECT_EQ(c.src_ip, 0xAC100002u);
    EXPECT_EQ(c.src_port, 0xC123u);
    // Full request identity is available for verdicts.
    EXPECT_EQ(c.service_id, 0xF4E7u);
    EXPECT_EQ(c.method_id, 0x0008u);
    EXPECT_EQ(c.client_id, 0x1234u);
    EXPECT_EQ(c.session_id, 0x0007u);
    // Recognized as the DUT's client-role request.
    EXPECT_TRUE(c.is_method_request_for(0xF4E7, 0x0008));
    EXPECT_FALSE(c.is_method_request_for(0xF4E7, 0x0009));  // wrong method
    EXPECT_FALSE(c.is_method_request_for(0xFFFE, 0x0008));  // wrong service
}

TEST(SomeIpCapturedClientRequest, FireAndForgetIsAClientRequest) {
    tc8::SomeIpFrame f{};
    f.service_id = 0xF4E7u;
    f.method_id = 0x0008u;
    f.message_type = static_cast<std::uint8_t>(tc8::someip::MessageType::REQUEST_NO_RETURN);
    tc8::SomeIpCaptured c{};
    tc8::fillSomeIpCapturedFromFrame(c, f);
    EXPECT_TRUE(c.is_method_request_for(0xF4E7, 0x0008));
}

TEST(SomeIpCapturedClientRequest, ResponseIsNotAClientRequest) {
    tc8::SomeIpFrame f{};
    f.service_id = 0xF4E7u;
    f.method_id = 0x0008u;
    f.message_type = static_cast<std::uint8_t>(tc8::someip::MessageType::RESPONSE);
    tc8::SomeIpCaptured c{};
    tc8::fillSomeIpCapturedFromFrame(c, f);
    EXPECT_FALSE(c.is_method_request_for(0xF4E7, 0x0008));
}

// CapturedFrameTiming::delta_from_listen_window_us — the boot/stimulus-relative
// measurement reference. Exercised through SomeIpCaptured (which derives from
// CapturedFrameTiming) since the SD_BEHAVIOR initial-delay cases that consume it
// use that context. The accessor is pure logic over the two timestamps; the
// runner stamps `listen_window_open_ts_us` once at listen-window-open.
TEST(CapturedFrameTimingListenWindow, UnsetReferenceReturnsZero) {
    tc8::SomeIpCaptured c{};
    // listen_window_open_ts_us == 0 (not stamped): unmeasurable -> 0, even with a
    // frame observed, so a `>= MIN` guard fails closed rather than passing.
    c.observed_ts_us = 1'700'000'000'000'000LL;
    EXPECT_EQ(c.delta_from_listen_window_us(), 0);

    // Window opened but no frame observed yet (observed_ts_us == 0) -> 0.
    tc8::SomeIpCaptured d{};
    d.listen_window_open_ts_us = 1'700'000'000'000'000LL;
    EXPECT_EQ(d.delta_from_listen_window_us(), 0);
}

TEST(CapturedFrameTimingListenWindow, PositiveGapMeasuredFromWindowOpen) {
    tc8::SomeIpCaptured c{};
    c.listen_window_open_ts_us = 1'700'000'000'000'000LL;
    c.observed_ts_us = c.listen_window_open_ts_us + 123'456LL;  // 123.456 ms later
    EXPECT_EQ(c.delta_from_listen_window_us(), 123'456LL);
}

TEST(CapturedFrameTimingListenWindow, FrameBeforeWindowOpenClampsToZero) {
    // A frame already in the capture ring before the listen window opened (the
    // DUT responded during stimulus) yields a negative raw difference; the
    // accessor clamps it to 0 so a nonsensical negative window never reaches a
    // guard or the trace.
    tc8::SomeIpCaptured c{};
    c.listen_window_open_ts_us = 1'700'000'000'000'000LL;
    c.observed_ts_us = c.listen_window_open_ts_us - 5'000LL;
    EXPECT_EQ(c.delta_from_listen_window_us(), 0);
}

TEST(CapturedFrameTimingListenWindow, IndependentOfFrameDeltaContract) {
    // The listen-window delta must not perturb frame_delta_us()'s
    // first-transition-returns-0 contract that the offer-to-offer guards rely
    // on: with no prior fired transition (prev_observed_ts_us == 0),
    // frame_delta_us() stays 0 even though the listen-window delta is non-zero.
    tc8::SomeIpCaptured c{};
    c.listen_window_open_ts_us = 1'700'000'000'000'000LL;
    c.observed_ts_us = c.listen_window_open_ts_us + 400'000LL;
    EXPECT_EQ(c.frame_delta_us(), 0);
    EXPECT_EQ(c.delta_from_listen_window_us(), 400'000LL);

    // Once a transition has fired (prev set), frame_delta_us() measures
    // frame-to-frame and the two accessors are independent.
    c.prev_observed_ts_us = c.listen_window_open_ts_us + 150'000LL;
    EXPECT_EQ(c.frame_delta_us(), 250'000LL);
    EXPECT_EQ(c.delta_from_listen_window_us(), 400'000LL);
}

// The runner stamps listen_window_open_ts_us ONCE in TestRunner::start(); a
// per-frame fill must NOT clobber it (the "stamped once, survives fills"
// invariant start() relies on). Drive the real fill path the dispatcher uses
// and assert the stamp survives while observed_ts_us IS updated from the frame.
TEST(CapturedFrameTimingListenWindow, SurvivesPerFrameFill) {
    tc8::SomeIpCaptured c{};
    c.listen_window_open_ts_us = 1'700'000'000'000'000LL;

    std::vector<std::uint8_t> payload(8, 0x00);
    tc8::SomeIpFrame f{};
    f.service_id = 0x1234;
    f.message_type = 0x80;
    f.observed_ts_us = c.listen_window_open_ts_us + 250'000LL;
    f.payload_data = payload.data();
    f.payload_len = static_cast<std::uint32_t>(payload.size());
    tc8::fillSomeIpCapturedFromFrame(c, f);

    EXPECT_EQ(c.listen_window_open_ts_us, 1'700'000'000'000'000LL);  // untouched
    EXPECT_EQ(c.observed_ts_us, c.listen_window_open_ts_us + 250'000LL);
    EXPECT_EQ(c.delta_from_listen_window_us(), 250'000LL);
}

// SOMEIPCLT DUT client-role SD recognizers: the DUT FindServices, Subscribes and
// StopSubscribes; these distinguish the three over the shared SD header
// (service_id 0xFFFF) and the first entry's type / TTL.
TEST(SomeIpCapturedDutSdRecognizers, FindSubscribeStopDiscriminated) {
    tc8::SomeIpCaptured c;
    c.service_id = 0xFFFF;  // SD header service.
    c.sd_entry_count = 1;

    // FindService (entry type 0x00) for service 0xF4E7.
    c.sd_entries[0].type = 0x00;
    c.sd_entries[0].service_id = 0xF4E7;
    EXPECT_TRUE(c.is_find_service_from_dut(0xF4E7));
    EXPECT_TRUE(c.is_find_service_from_dut(0xFFFF));   // wildcard matches any service
    EXPECT_FALSE(c.is_find_service_from_dut(0xF4E8));  // wrong service
    EXPECT_FALSE(c.is_subscribe_for(0xF4E7, 0x0005));  // a Find is not a Subscribe

    // SubscribeEventgroup (entry type 0x06) with a live TTL.
    c.sd_entries[0].type = 0x06;
    c.sd_entries[0].ttl = 3;
    c.sd_entries[0].eventgroup_id = 0x0005;
    EXPECT_TRUE(c.is_subscribe_for(0xF4E7, 0x0005));
    EXPECT_FALSE(c.is_subscribe_for(0xF4E7, 0x0001));   // wrong eventgroup
    EXPECT_FALSE(c.is_subscribe_for(0xF4E8, 0x0005));   // wrong service
    EXPECT_FALSE(c.is_stop_subscribe(0xF4E7, 0x0005));  // TTL > 0 is not a Stop

    // StopSubscribe = same entry type 0x06 with TTL 0.
    c.sd_entries[0].ttl = 0;
    EXPECT_TRUE(c.is_stop_subscribe(0xF4E7, 0x0005));
    EXPECT_FALSE(c.is_subscribe_for(0xF4E7, 0x0005));   // TTL 0 is not a live Subscribe

    // A non-SD frame (header service != 0xFFFF) matches none of them.
    c.service_id = 0xF4E7;
    EXPECT_FALSE(c.is_find_service_from_dut(0xFFFF));
    EXPECT_FALSE(c.is_stop_subscribe(0xF4E7, 0x0005));
}

// Pins decodeSdEntry's Reserved:12 | Counter:4 split of a SubscribeEventgroup
// entry's bytes 12..13 into the same named fields the stimulus builder packs
// (`(entry_reserved << 4) | (counter & 0x0F)`), so a verdict reads back what a
// case set. Guards against an accidental nibble swap in the decoder.
TEST(SomeIpCapturedSdEntry, SubscribeEntryReservedCounterSplit) {
    std::uint8_t raw[16] = {};
    raw[0] = 0x06;   // SubscribeEventgroup entry.
    raw[12] = 0xAB;  // bytes 12..13 = 0xABC3 -> Reserved=0xABC, Counter=0x3.
    raw[13] = 0xC3;
    tc8::SdEntry e;
    tc8::decodeSdEntry(e, raw);
    EXPECT_EQ(e.entry_reserved, 0x0ABCu);  // high 12 bits
    EXPECT_EQ(e.counter, 0x3u);            // low 4 bits

    // Pure reserved field (counter zero).
    raw[12] = 0xFF;
    raw[13] = 0xF0;
    tc8::decodeSdEntry(e, raw);
    EXPECT_EQ(e.entry_reserved, 0x0FFFu);
    EXPECT_EQ(e.counter, 0x0u);

    // All-distinct nibbles with a full 4-bit counter — exercises the upper
    // counter bits (0x4/0x8) and 0xF, strengthening swap / mask-width detection.
    raw[12] = 0x24;
    raw[13] = 0x6F;
    tc8::decodeSdEntry(e, raw);
    EXPECT_EQ(e.entry_reserved, 0x246u);
    EXPECT_EQ(e.counter, 0xFu);

    // Spec-canonical all-zero entry decodes both to 0.
    raw[12] = 0x00;
    raw[13] = 0x00;
    tc8::decodeSdEntry(e, raw);
    EXPECT_EQ(e.entry_reserved, 0x0000u);
    EXPECT_EQ(e.counter, 0x0u);
}
