// Unit coverage for the tester-side ARP responder (src/stimulus/arp_responder.*).
//
// The pure reply-builder (`buildArpReplyForRequest`) carries the match decision
// and reply wire-layout, so it is exercised here with no privilege: a Request
// for an armed IP yields a correct unicast Reply, and every non-matching shape
// (wrong opcode, unarmed target, truncated, non-ARP EtherType) yields nullopt.
// The live socket/thread plumbing of `ArpResponder` itself needs a veth pair
// and CAP_NET_RAW, so it is proven in arp_responder_privileged_test.cpp.
//
// `macOfInterface` is covered alongside, since the responder relies on it to
// advertise the tester's real interface MAC.

#include "stimulus/arp_responder.h"

#include <arpa/inet.h>

#include <array>
#include <cstdint>
#include <vector>

#include <gtest/gtest.h>

#include "stimulus/arp_builder.h"
#include "stimulus/iface_addr.h"

namespace {

using tc8::stimulus::ArpBinding;
using tc8::stimulus::buildArpReplyForRequest;

// Dotted-quad to the network-byte-order uint32 the binding / wire fields use
// (bytes laid out MSB-first on the wire, matching inet_pton / ipv4OfInterface).
std::uint32_t ipBe(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) {
    return htonl((static_cast<std::uint32_t>(a) << 24) | (static_cast<std::uint32_t>(b) << 16) |
                 (static_cast<std::uint32_t>(c) << 8) | d);
}

constexpr std::array<std::uint8_t, 6> kDutMac{0x02, 0x00, 0x00, 0x00, 0x00, 0xD0};
constexpr std::array<std::uint8_t, 6> kTesterMac{0x02, 0x00, 0x00, 0x00, 0x00, 0x7E};

// Wire offsets of an Ethernet-II + IPv4/Ethernet ARP frame.
constexpr std::size_t kOffEthDst = 0;
constexpr std::size_t kOffEthSrc = 6;
constexpr std::size_t kOffEtherType = 12;
constexpr std::size_t kOffOpcode = 20;
constexpr std::size_t kOffSenderHw = 22;
constexpr std::size_t kOffSenderIp = 28;
constexpr std::size_t kOffTargetHw = 32;
constexpr std::size_t kOffTargetIp = 38;

std::uint16_t be16At(const std::vector<std::uint8_t>& f, std::size_t off) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(f[off]) << 8) | f[off + 1]);
}

std::array<std::uint8_t, 6> macAt(const std::vector<std::uint8_t>& f, std::size_t off) {
    std::array<std::uint8_t, 6> m{};
    for (std::size_t i = 0; i < 6; ++i) m[i] = f[off + i];
    return m;
}

std::uint32_t ipAt(const std::vector<std::uint8_t>& f, std::size_t off) {
    std::uint32_t v = 0;
    for (std::size_t i = 0; i < 4; ++i) {
        reinterpret_cast<std::uint8_t*>(&v)[i] = f[off + i];
    }
    return v;
}

TEST(BuildArpReply, AnswersRequestForArmedIp) {
    const std::uint32_t spoofed_ip = ipBe(172, 16, 0, 9);
    const std::uint32_t dut_ip = ipBe(172, 16, 0, 2);
    const std::vector<ArpBinding> bindings{{spoofed_ip, kTesterMac}};

    // DUT asks "who has the spoofed source IP?"; eth_src defaults to sender_hw.
    const auto request = tc8::stimulus::buildArpRequest(kDutMac, dut_ip, spoofed_ip);
    const auto reply = buildArpReplyForRequest(request.data(), request.size(), bindings);

    ASSERT_TRUE(reply.has_value());
    EXPECT_EQ(reply->size(), 42U);
    // EtherType ARP, opcode Reply.
    EXPECT_EQ(be16At(*reply, kOffEtherType), 0x0806);
    EXPECT_EQ(be16At(*reply, kOffOpcode), 0x0002);
    // Sender = the armed binding (the spoofed IP now resolves to the tester MAC).
    EXPECT_EQ(macAt(*reply, kOffSenderHw), kTesterMac);
    EXPECT_EQ(ipAt(*reply, kOffSenderIp), spoofed_ip);
    // Target = the requester, so the answer is a unicast back to the DUT.
    EXPECT_EQ(macAt(*reply, kOffTargetHw), kDutMac);
    EXPECT_EQ(ipAt(*reply, kOffTargetIp), dut_ip);
    // Ethernet framing: unicast dst = requester, src = the advertised MAC.
    EXPECT_EQ(macAt(*reply, kOffEthDst), kDutMac);
    EXPECT_EQ(macAt(*reply, kOffEthSrc), kTesterMac);
}

TEST(BuildArpReply, PicksTheMatchingBindingAmongSeveral) {
    const std::uint32_t ip1 = ipBe(172, 16, 0, 9);
    const std::uint32_t ip2 = ipBe(172, 16, 0, 10);
    const std::array<std::uint8_t, 6> mac2{0x02, 0, 0, 0, 0, 0xB2};
    const std::vector<ArpBinding> bindings{{ip1, kTesterMac}, {ip2, mac2}};

    const auto request = tc8::stimulus::buildArpRequest(kDutMac, ipBe(172, 16, 0, 2), ip2);
    const auto reply = buildArpReplyForRequest(request.data(), request.size(), bindings);

    ASSERT_TRUE(reply.has_value());
    EXPECT_EQ(ipAt(*reply, kOffSenderIp), ip2);
    EXPECT_EQ(macAt(*reply, kOffSenderHw), mac2);
}

TEST(BuildArpReply, IgnoresRequestForUnarmedIp) {
    const std::vector<ArpBinding> bindings{{ipBe(172, 16, 0, 9), kTesterMac}};
    // Request targets a different IP than the one armed.
    const auto request =
        tc8::stimulus::buildArpRequest(kDutMac, ipBe(172, 16, 0, 2), ipBe(172, 16, 0, 99));
    EXPECT_FALSE(buildArpReplyForRequest(request.data(), request.size(), bindings).has_value());
}

TEST(BuildArpReply, IgnoresNonRequestOpcode) {
    const std::uint32_t ip = ipBe(172, 16, 0, 9);
    const std::vector<ArpBinding> bindings{{ip, kTesterMac}};
    // A gratuitous Reply (opcode 2) for the armed IP must not trigger a reply —
    // the responder only answers actual Requests (and this is also how it avoids
    // reacting to its own egress).
    const auto grat = tc8::stimulus::buildGratuitousArpResponse(kDutMac, ip);
    EXPECT_FALSE(buildArpReplyForRequest(grat.data(), grat.size(), bindings).has_value());
}

TEST(BuildArpReply, IgnoresTruncatedFrame) {
    const std::vector<ArpBinding> bindings{{ipBe(172, 16, 0, 9), kTesterMac}};
    auto request =
        tc8::stimulus::buildArpRequest(kDutMac, ipBe(172, 16, 0, 2), ipBe(172, 16, 0, 9));
    request.resize(41);  // one byte short of the 42-byte minimum
    EXPECT_FALSE(buildArpReplyForRequest(request.data(), request.size(), bindings).has_value());
    EXPECT_FALSE(buildArpReplyForRequest(nullptr, 0, bindings).has_value());
}

TEST(BuildArpReply, IgnoresNonArpEtherType) {
    const std::vector<ArpBinding> bindings{{ipBe(172, 16, 0, 9), kTesterMac}};
    auto request =
        tc8::stimulus::buildArpRequest(kDutMac, ipBe(172, 16, 0, 2), ipBe(172, 16, 0, 9));
    request[kOffEtherType] = 0x08;  // 0x0800 (IPv4) instead of 0x0806 (ARP)
    request[kOffEtherType + 1] = 0x00;
    EXPECT_FALSE(buildArpReplyForRequest(request.data(), request.size(), bindings).has_value());
}

TEST(BuildArpReply, EmptyBindingsNeverAnswers) {
    const auto request =
        tc8::stimulus::buildArpRequest(kDutMac, ipBe(172, 16, 0, 2), ipBe(172, 16, 0, 9));
    EXPECT_FALSE(buildArpReplyForRequest(request.data(), request.size(), {}).has_value());
}

TEST(MacResolver, ResolvesLoopback) {
    // `lo` always exists; SIOCGIFHWADDR succeeds and reports the all-zero
    // loopback hardware address as a value (success), not nullopt.
    const auto mac = tc8::stimulus::macOfInterface("lo");
    ASSERT_TRUE(mac.has_value());
    EXPECT_EQ(*mac, (std::array<std::uint8_t, 6>{0, 0, 0, 0, 0, 0}));
}

TEST(MacResolver, NulloptForMissingInterface) {
    EXPECT_FALSE(tc8::stimulus::macOfInterface("tc8_no_such_if0").has_value());
    EXPECT_FALSE(tc8::stimulus::macOfInterface("").has_value());
}

}  // namespace
