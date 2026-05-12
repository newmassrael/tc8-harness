// Regression guard for `tc8::iface_enum::dedupeByName`.
//
// History: §4.7.6.5 DHCPV4_CLIENT_USAGE_01 silently regressed on
// 2026-05-04 when `setup-netns.sh` started attaching a secondary IPv4
// (172.16.0.5 alias for UI_07/_08) to `veth-dut-W`. Linux's
// getifaddrs(3) returns one ifaddrs entry per AF_INET address, so the
// downstream enumeration in `upper_tester_server.cpp` collected two
// IfaceInfo records for the same veth — both with the same MAC.
// `dhcpv4_clients_[1]` then aliased `dhcpv4_clients_[0]` and the case
// observed two DHCPDISCOVERs with one shared chaddr (RFC 2131 §3.6
// MUST violation). These tests pin the dedupe semantics so a future
// refactor cannot silently reintroduce the collision.

#include "tc8/iface_enumeration.h"

#include <gtest/gtest.h>

#include <array>

namespace {

using ::tc8::iface_enum::IfaceInfo;
using ::tc8::iface_enum::dedupeByName;

constexpr std::array<std::uint8_t, 6> kMacA{
    0x02, 0x00, 0x00, 0x00, 0x00, 0xA1};
constexpr std::array<std::uint8_t, 6> kMacB{
    0x02, 0x00, 0x00, 0x00, 0x00, 0xB2};

IfaceInfo make(const char* name,
               const std::array<std::uint8_t, 6>& mac,
               std::uint32_t ip_be) {
    IfaceInfo info;
    info.name  = name;
    info.mac   = mac;
    info.ip_be = ip_be;
    return info;
}

TEST(IfaceEnumDedupeByName, EmptyInput) {
    EXPECT_TRUE(dedupeByName({}).empty());
}

TEST(IfaceEnumDedupeByName, SinglePassThrough) {
    auto out = dedupeByName({make("veth-dut-0", kMacA, 0x0200010AU)});
    ASSERT_EQ(out.size(), 1U);
    EXPECT_EQ(out[0].name, "veth-dut-0");
}

TEST(IfaceEnumDedupeByName, DistinctNamesPreserveOrder) {
    auto out = dedupeByName({
        make("veth-dut-0",  kMacA, 0x0200010AU),
        make("veth-dut2-0", kMacB, 0x0200110AU),
    });
    ASSERT_EQ(out.size(), 2U);
    EXPECT_EQ(out[0].name, "veth-dut-0");
    EXPECT_EQ(out[1].name, "veth-dut2-0");
}

// The original USAGE_01 collision shape: two AF_INET addresses on the
// primary veth, then the secondary veth. Dedupe must collapse the
// first two and leave the secondary's distinct MAC reachable at index
// 1 after the caller-side sort. First-seen wins so the primary IP
// (172.16.0.2, added first by setup-netns.sh) survives — critical for
// the legacy `iface_ip_be_` / §4.4 / §4.5 / §4.8 surface.
TEST(IfaceEnumDedupeByName, AliasAddressCollapsesToFirst) {
    auto out = dedupeByName({
        make("veth-dut-0",  kMacA, 0x0200010AU),  // 172.16.0.2 (primary)
        make("veth-dut-0",  kMacA, 0x0500010AU),  // 172.16.0.5 (alias)
        make("veth-dut2-0", kMacB, 0x0200110AU),  // 172.17.0.2 (secondary)
    });
    ASSERT_EQ(out.size(), 2U);
    EXPECT_EQ(out[0].name, "veth-dut-0");
    EXPECT_EQ(out[0].ip_be, 0x0200010AU);  // first-seen = primary IP
    EXPECT_EQ(out[0].mac,   kMacA);
    EXPECT_EQ(out[1].name, "veth-dut2-0");
    EXPECT_EQ(out[1].mac,   kMacB);
}

// Defence in depth: even if a future kernel quirk produces three
// identical-name entries, dedupe must still leave exactly one.
TEST(IfaceEnumDedupeByName, MultipleDuplicatesCollapseToOne) {
    auto out = dedupeByName({
        make("veth-dut-0", kMacA, 0x0200010AU),
        make("veth-dut-0", kMacA, 0x0500010AU),
        make("veth-dut-0", kMacA, 0x0600010AU),
    });
    ASSERT_EQ(out.size(), 1U);
    EXPECT_EQ(out[0].ip_be, 0x0200010AU);
}

// Order independence on which `getifaddrs` entry-position the alias
// lands at: even if the kernel returns the alias before the primary,
// dedupe is a pure function of input order — the test asserts the
// contract ("first-seen wins") rather than the kernel's behaviour.
TEST(IfaceEnumDedupeByName, AliasBeforePrimaryStillKeepsFirstSeen) {
    auto out = dedupeByName({
        make("veth-dut-0", kMacA, 0x0500010AU),  // alias listed first
        make("veth-dut-0", kMacA, 0x0200010AU),  // primary listed second
    });
    ASSERT_EQ(out.size(), 1U);
    EXPECT_EQ(out[0].ip_be, 0x0500010AU);
}

}  // namespace
