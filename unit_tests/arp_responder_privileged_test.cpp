// Live coverage for the ArpResponder socket plumbing (the part the pure
// arp_responder_test.cpp cannot reach). Runs the responder on one end of a veth
// pair, injects a DUT-style ARP Request on the peer end, drives onReadable() (as
// the capture loop does — there is no worker thread), and verifies a correct
// unicast Reply comes back, proving the AF_PACKET RX bind, the non-blocking
// drain, and the egress reply path all work end to end.
//
// Needs CAP_NET_RAW (the responder socket) and CAP_NET_ADMIN (veth creation), so
// it self-skips without privilege and is also registered under run-netns-test.sh
// so the hosted/self-hosted CTest exercises the success path inside an
// unprivileged user+net namespace (no sudo). Same gating idiom as the
// posix_neighbor_privileged / link_state_privileged tests.

#include "stimulus/arp_responder.h"

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cstdint>
#include <cstring>

#include <gtest/gtest.h>

#include "netns_test_util.h"
#include "stimulus/arp_builder.h"

namespace {

using namespace tc8::testutil;

std::uint32_t ipBe(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) {
    return htonl((static_cast<std::uint32_t>(a) << 24) | (static_cast<std::uint32_t>(b) << 16) |
                 (static_cast<std::uint32_t>(c) << 8) | d);
}

// A bound AF_PACKET/ARP capture socket on `iface`, or -1. Used by the test to
// observe the responder's Reply on the peer end of the veth pair.
int openArpCapture(const char* iface) {
    const int s = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (s < 0) {
        return -1;
    }
    const unsigned idx = ::if_nametoindex(iface);
    if (idx == 0) {
        ::close(s);
        return -1;
    }
    sockaddr_ll ll{};
    ll.sll_family = AF_PACKET;
    ll.sll_protocol = htons(ETH_P_ARP);
    ll.sll_ifindex = static_cast<int>(idx);
    if (::bind(s, reinterpret_cast<sockaddr*>(&ll), sizeof(ll)) < 0) {
        ::close(s);
        return -1;
    }
    return s;
}

TEST(ArpResponderLive, AnswersRequestOnVethPeer) {
    if (!hasNetAdmin()) {
        GTEST_SKIP() << "needs CAP_NET_ADMIN (run under run-netns-test.sh)";
    }
    constexpr const char* kA = "tc8arpa";  // responder side
    constexpr const char* kB = "tc8arpb";  // injector / capture side
    deleteIface(kA);                        // clear any stale leftover from an aborted run
    if (!createVethPair(kA, kB)) {
        GTEST_SKIP() << "veth pair unavailable on this kernel";
    }
    ScopeExit pair_cleanup([&] { deleteIface(kA); });

    const std::uint32_t spoofed_ip = ipBe(172, 16, 0, 9);
    const std::uint32_t dut_ip = ipBe(172, 16, 0, 2);
    const std::array<std::uint8_t, 6> tester_mac{0x02, 0, 0, 0, 0, 0x7E};
    const std::array<std::uint8_t, 6> dut_mac{0x02, 0, 0, 0, 0, 0xD0};

    const int cap = openArpCapture(kB);
    ASSERT_GE(cap, 0) << "could not open ARP capture on peer";
    ScopeExit cap_cleanup([&] { ::close(cap); });

    // Socket is bound in the constructor, so frames are queued the moment the
    // responder exists. There is no worker thread — the test drives onReadable()
    // on the responder's fd exactly as the CLI capture loop does.
    tc8::stimulus::ArpResponder responder(kA, {{spoofed_ip, tester_mac}});
    ASSERT_TRUE(responder.ok());
    ASSERT_GE(responder.pollFd(), 0);

    // DUT asks "who has the spoofed source IP?" on the peer end; the frame
    // crosses the veth to the responder.
    const auto request = tc8::stimulus::buildArpRequest(dut_mac, dut_ip, spoofed_ip);
    ASSERT_EQ(tc8::stimulus::sendRawEthernet(request, kB), 0);

    // Poll BOTH the responder fd (to drive onReadable, which answers) and the
    // peer capture (to observe the Reply), within a bounded budget. Skip our own
    // injected Request (PACKET_OUTGOING) and any non-matching ARP traffic.
    bool got_reply = false;
    for (int waited_ms = 0; waited_ms < 2000 && !got_reply;) {
        pollfd p[2];
        p[0] = pollfd{responder.pollFd(), POLLIN, 0};
        p[1] = pollfd{cap, POLLIN, 0};
        const int rc = ::poll(p, 2, 100);
        if (rc <= 0) {
            waited_ms += 100;
            continue;
        }
        if (p[0].revents & POLLIN) {
            responder.onReadable();  // read the Request(s) and send the Reply
        }
        if (!(p[1].revents & POLLIN)) {
            continue;
        }
        std::uint8_t buf[256];
        sockaddr_ll from{};
        socklen_t fl = sizeof(from);
        const ssize_t n =
            ::recvfrom(cap, buf, sizeof(buf), 0, reinterpret_cast<sockaddr*>(&from), &fl);
        if (n < 42) {
            continue;
        }
        if (from.sll_pkttype == PACKET_OUTGOING) {
            continue;  // our own injected Request echoed on egress
        }
        const std::uint16_t ethertype = static_cast<std::uint16_t>((buf[12] << 8) | buf[13]);
        const std::uint16_t opcode = static_cast<std::uint16_t>((buf[20] << 8) | buf[21]);
        if (ethertype != 0x0806 || opcode != 0x0002) {
            continue;
        }
        std::uint32_t sender_ip = 0;
        std::memcpy(&sender_ip, buf + 28, 4);  // ARP sender protocol address
        if (sender_ip != spoofed_ip) {
            continue;
        }
        // The spoofed IP now resolves to the advertised tester MAC, addressed
        // back to the requesting DUT.
        EXPECT_EQ(0, std::memcmp(buf + 22, tester_mac.data(), 6));  // ARP sender_hw
        EXPECT_EQ(0, std::memcmp(buf + 32, dut_mac.data(), 6));     // ARP target_hw
        EXPECT_EQ(0, std::memcmp(buf + 0, dut_mac.data(), 6));      // Ethernet dst (unicast)
        got_reply = true;
    }

    EXPECT_TRUE(got_reply) << "ArpResponder did not answer the Request";

    // onReadable() increments repliesSent() synchronously before returning, so by
    // the time the Reply was observed the counter is already set — no race.
    EXPECT_GE(responder.repliesSent(), 1U);
}

}  // namespace
