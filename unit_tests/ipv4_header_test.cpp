// The RFC 791 §3.1 header walk (tc8/wire/ipv4_header.h): every header the RFC allows is
// read, the options are walked option by option, and what the walk finds is recorded
// rather than refused.
#include <cstdint>
#include <cstring>
#include <vector>

#include <gtest/gtest.h>

#include "tc8/wire/ipv4_header.h"

namespace {

using ::tc8::wire::decodeIpv4Header;

// A header with `options` after the fixed 20 bytes; IHL and Total Length follow them.
std::vector<std::uint8_t> header(const std::vector<std::uint8_t> &options, std::uint8_t ihl_override = 0) {
    const auto ihl = static_cast<std::uint8_t>(ihl_override != 0 ? ihl_override : 5 + options.size() / 4);
    const auto total = static_cast<std::uint16_t>(20 + options.size());
    std::vector<std::uint8_t> h = {
        static_cast<std::uint8_t>(0x40 | ihl), 0x10, static_cast<std::uint8_t>(total >> 8),
        static_cast<std::uint8_t>(total), 0xAB, 0xCD, 0x40, 0x00, 0x40, 0x01, 0x12, 0x34,
        192, 168, 0, 1, 192, 168, 0, 10};
    h.insert(h.end(), options.begin(), options.end());
    return h;
}

TEST(Ipv4HeaderDecode, ReadsTheFixedFields) {
    const auto h = header({});
    const auto ip = decodeIpv4Header(h.data(), h.size());
    ASSERT_TRUE(ip.has_value());
    EXPECT_EQ(ip->version, 4);
    EXPECT_EQ(ip->ihl, 5);
    EXPECT_EQ(ip->tos, 0x10);
    EXPECT_EQ(ip->total_length, 20);
    EXPECT_EQ(ip->identification, 0xABCD);
    EXPECT_EQ(ip->flags, 0x2);  // DF
    EXPECT_EQ(ip->fragment_offset, 0);
    EXPECT_EQ(ip->ttl, 64);
    EXPECT_EQ(ip->protocol, 1);
    EXPECT_EQ(ip->header_checksum, 0x1234);
    const std::uint8_t src[4] = {192, 168, 0, 1};
    std::uint32_t src_be = 0;
    std::memcpy(&src_be, src, 4);
    EXPECT_EQ(ip->src_be, src_be);
    EXPECT_EQ(ip->options_len, 0u);
    EXPECT_FALSE(ip->end_of_list_at.has_value());
}

// RFC 791 §3.1: the list may end with End of Option List, and zero padding follows to
// the 32-bit boundary. This is the shape libtins refused.
TEST(Ipv4HeaderDecode, EndOfListFollowedByZeroPaddingIsNormal) {
    const auto h = header({0x00, 0x00, 0x00, 0x00});
    const auto ip = decodeIpv4Header(h.data(), h.size());
    ASSERT_TRUE(ip.has_value());
    EXPECT_EQ(ip->options_len, 4u);
    ASSERT_TRUE(ip->end_of_list_at.has_value());
    EXPECT_EQ(*ip->end_of_list_at, 20u);
    EXPECT_FALSE(ip->padding_nonzero);
    EXPECT_FALSE(ip->options_malformed);
}

// A zero byte inside another option's data is data, not the end of the list: Record
// Route with an empty slot, two No-Operations, End of Option List, two bytes of padding.
TEST(Ipv4HeaderDecode, AZeroInsideAnOptionIsNotTheEndOfTheList) {
    const auto h = header({0x07, 0x07, 0x04, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00});
    const auto ip = decodeIpv4Header(h.data(), h.size());
    ASSERT_TRUE(ip.has_value());
    ASSERT_TRUE(ip->end_of_list_at.has_value());
    EXPECT_EQ(*ip->end_of_list_at, 20u + 9u);
    EXPECT_FALSE(ip->options_malformed);
}

// RFC 791 Security (type 130, length 11): nine bytes of data, which may be zero, then
// End of Option List at the eleventh byte past the option and zero padding.
TEST(Ipv4HeaderDecode, ASecurityOptionIsWalkedByItsLength) {
    const auto h = header({0x82, 0x0B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
    const auto ip = decodeIpv4Header(h.data(), h.size());
    ASSERT_TRUE(ip.has_value());
    ASSERT_TRUE(ip->end_of_list_at.has_value());
    EXPECT_EQ(*ip->end_of_list_at, 20u + 11u);
    EXPECT_FALSE(ip->padding_nonzero);
    EXPECT_FALSE(ip->options_malformed);
}

TEST(Ipv4HeaderDecode, OptionsFillingTheAreaNeedNoEndOfList) {
    const auto h = header({0x01, 0x01, 0x01, 0x01});
    const auto ip = decodeIpv4Header(h.data(), h.size());
    ASSERT_TRUE(ip.has_value());
    EXPECT_FALSE(ip->end_of_list_at.has_value());
    EXPECT_FALSE(ip->options_malformed);
}

// RFC 791: "The padding is zero." A sender that pads with something else is recorded,
// and its header is still read.
TEST(Ipv4HeaderDecode, NonZeroPaddingIsRecordedNotRefused) {
    const auto h = header({0x00, 0x00, 0xFF, 0x00});
    const auto ip = decodeIpv4Header(h.data(), h.size());
    ASSERT_TRUE(ip.has_value());
    EXPECT_TRUE(ip->padding_nonzero);
}

TEST(Ipv4HeaderDecode, AnOptionPastTheAreaOrShorterThanItsOwnHeaderIsMalformed) {
    const auto overrun = header({0x07, 0x09, 0x04, 0x00});
    const auto ip1 = decodeIpv4Header(overrun.data(), overrun.size());
    ASSERT_TRUE(ip1.has_value());
    EXPECT_TRUE(ip1->options_malformed);
    EXPECT_FALSE(ip1->end_of_list_at.has_value());

    const auto too_short = header({0x07, 0x01, 0x00, 0x00});
    const auto ip2 = decodeIpv4Header(too_short.data(), too_short.size());
    ASSERT_TRUE(ip2.has_value());
    EXPECT_TRUE(ip2->options_malformed);

    const auto no_length_byte = header({0x01, 0x01, 0x01, 0x07});
    const auto ip3 = decodeIpv4Header(no_length_byte.data(), no_length_byte.size());
    ASSERT_TRUE(ip3.has_value());
    EXPECT_TRUE(ip3->options_malformed);
}

// A packet typed IPv4 with another Version is a stimulus a case sends on purpose; its
// header is read and the Version reported as it stands.
TEST(Ipv4HeaderDecode, AnotherVersionIsReportedNotRefused) {
    auto v6 = header({});
    v6[0] = 0x65;
    const auto ip = decodeIpv4Header(v6.data(), v6.size());
    ASSERT_TRUE(ip.has_value());
    EXPECT_EQ(ip->version, 6);
    EXPECT_EQ(ip->ihl, 5);
}

TEST(Ipv4HeaderDecode, AHeaderThatCannotBeLocatedIsEmpty) {
    const auto h = header({});
    EXPECT_FALSE(decodeIpv4Header(h.data(), 19).has_value());     // fewer than 20 bytes
    EXPECT_FALSE(decodeIpv4Header(nullptr, 20).has_value());

    const auto ihl4 = header({}, 4);
    EXPECT_FALSE(decodeIpv4Header(ihl4.data(), ihl4.size()).has_value());  // IHL below 5

    const auto ihl6 = header({}, 6);
    EXPECT_FALSE(decodeIpv4Header(ihl6.data(), ihl6.size()).has_value());  // IHL past the bytes
}

}  // namespace
