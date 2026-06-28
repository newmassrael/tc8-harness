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
#include <memory>
#include <type_traits>
#include <vector>

#include <gtest/gtest.h>

#include "stimulus/arp_builder.h"
#include "stimulus/iface_addr.h"
#include "tc8/pollable_service.h"

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

TEST(BuildArpReply, IgnoresNonEthernetIpv4Arp) {
    // ARP header field offsets within the frame: hw_type@14, proto_type@16,
    // hw_addr_len@18, proto_addr_len@19. Each guard must reject independently.
    const std::vector<ArpBinding> bindings{{ipBe(172, 16, 0, 9), kTesterMac}};
    const std::uint32_t dut_ip = ipBe(172, 16, 0, 2);
    const std::uint32_t tgt_ip = ipBe(172, 16, 0, 9);

    auto bad_hw_type = tc8::stimulus::buildArpRequest(kDutMac, dut_ip, tgt_ip);
    bad_hw_type[15] = 0x06;  // hw_type 0x0006 instead of 0x0001 (Ethernet)
    EXPECT_FALSE(buildArpReplyForRequest(bad_hw_type.data(), bad_hw_type.size(), bindings));

    auto bad_proto = tc8::stimulus::buildArpRequest(kDutMac, dut_ip, tgt_ip);
    bad_proto[16] = 0x86;  // proto_type 0x86DD (IPv6) instead of 0x0800 (IPv4)
    bad_proto[17] = 0xDD;
    EXPECT_FALSE(buildArpReplyForRequest(bad_proto.data(), bad_proto.size(), bindings));

    auto bad_hlen = tc8::stimulus::buildArpRequest(kDutMac, dut_ip, tgt_ip);
    bad_hlen[18] = 8;  // hw_addr_len 8 instead of 6
    EXPECT_FALSE(buildArpReplyForRequest(bad_hlen.data(), bad_hlen.size(), bindings));
}

TEST(BuildArpReply, IgnoresTruncatedArpBody) {
    // A valid Ethernet header but an ARP body cut short of the 42-byte minimum
    // (target_ip ends at byte 41) must be rejected without an out-of-bounds read.
    const std::vector<ArpBinding> bindings{{ipBe(172, 16, 0, 9), kTesterMac}};
    auto request =
        tc8::stimulus::buildArpRequest(kDutMac, ipBe(172, 16, 0, 2), ipBe(172, 16, 0, 9));
    request.resize(30);  // 14 B Ethernet + only 16 B of the 28 B ARP body
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

// --- IPollableService ownership seam (IBackgroundServiceOwner::adoptService) ---

// ArpResponder must model tc8::IPollableService so a case can adopt it onto the
// runner and the capture loop can poll/drain it.
static_assert(
    std::is_base_of_v<::tc8::IPollableService, tc8::stimulus::ArpResponder>,
    "ArpResponder must model tc8::IPollableService");

// Records its own destruction and counts onReadable() calls, standing in for
// ArpResponder without AF_PACKET / CAP_NET_RAW.
class FakePollableService : public ::tc8::IPollableService {
public:
    FakePollableService(int fd, bool& destroyed_flag) : fd_(fd), destroyed_(destroyed_flag) {}
    ~FakePollableService() override { destroyed_ = true; }
    int  pollFd() const override { return fd_; }
    void onReadable() override { ++reads_; }
    int  reads() const { return reads_; }

private:
    int   fd_;
    int   reads_ = 0;
    bool& destroyed_;
};

// The runner owns adopted services in a vector<unique_ptr<IPollableService>> and
// destroys them through the base pointer at teardown. Proves the destructor is
// virtual — a non-virtual one would leak the live socket fd past the run.
TEST(PollableServiceSeam, OwnedServiceDestroyedThroughBasePointer) {
    bool destroyed = false;
    {
        std::vector<std::unique_ptr<::tc8::IPollableService>> owned;
        owned.push_back(std::make_unique<FakePollableService>(/*fd=*/-1, destroyed));
        EXPECT_FALSE(destroyed);  // still owned while the capture window is open
    }
    EXPECT_TRUE(destroyed);  // vector teardown ran the RAII destructor
}

// The capture loop drives a service through the base interface — pollFd() to add
// it to the drain set, onReadable() to answer; verify both dispatch to the
// concrete service polymorphically.
TEST(PollableServiceSeam, PollFdAndOnReadableDispatchPolymorphically) {
    bool destroyed = false;
    FakePollableService svc(/*fd=*/7, destroyed);
    ::tc8::IPollableService& base = svc;
    EXPECT_EQ(base.pollFd(), 7);
    base.onReadable();
    base.onReadable();
    EXPECT_EQ(svc.reads(), 2);
}

}  // namespace
