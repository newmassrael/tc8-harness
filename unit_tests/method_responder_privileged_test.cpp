// Live coverage for the MethodResponder socket plumbing (the part the pure
// method_responder_test.cpp cannot reach): the AF_PACKET RX bind, the non-blocking
// drain, the PACKET_OUTGOING self-skip, the reply build via the caller's builder,
// and the emitMethodReply egress + repliesSent accounting. Runs the responder on
// one end of a veth pair (with an IPv4 + a static neighbor so emitMethodReply can
// bind a UDP socket and the reply egresses deterministically), injects a DUT-style
// SOME/IP Method Request on the peer end, drives onReadable() exactly as the
// capture loop does, and verifies the emitted SOME/IP Response on the responder's
// own egress.
//
// Needs CAP_NET_RAW (the AF_PACKET sockets) and CAP_NET_ADMIN (veth + addr +
// neighbor), so it self-skips without privilege and is registered under
// run-netns-test.sh so the hosted/self-hosted CTest exercises the success path in
// an unprivileged user+net namespace (no sudo). Same idiom as
// arp_responder_privileged_test.

#include "stimulus/method_responder.h"

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

#include <gtest/gtest.h>

#include "netns_test_util.h"
#include "tc8/someip/protocol.h"
#include "tc8/someip/wire.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/udp_emit.h"

namespace {

using namespace tc8::testutil;

constexpr std::uint16_t kServiceId = 0xF4E7;   // SERVICE-ID-1 / echoUINT8 defaults
constexpr std::uint16_t kMethodId = 0x0008;
constexpr std::uint16_t kServicePort = 30509;  // tester's offered service port
constexpr std::uint16_t kClientPort = 51000;   // DUT client's ephemeral source

// A bound AF_PACKET/IP capture socket on `iface`, or -1. Used on the peer end to
// observe the responder's Reply arriving across the veth (the same topology the
// ARP responder live test uses).
int openIpCapture(const char* iface) {
    const int s = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
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
    ll.sll_protocol = htons(ETH_P_IP);
    ll.sll_ifindex = static_cast<int>(idx);
    if (::bind(s, reinterpret_cast<sockaddr*>(&ll), sizeof(ll)) < 0) {
        ::close(s);
        return -1;
    }
    return s;
}

TEST(MethodResponderLive, AnswersRequestOnVethPeer) {
    if (!hasNetAdmin()) {
        GTEST_SKIP() << "needs CAP_NET_ADMIN (run under run-netns-test.sh)";
    }
    constexpr const char* kA = "tc8mra";  // responder side (carries the service IP)
    constexpr const char* kB = "tc8mrb";  // injector side
    deleteIface(kA);                      // clear any stale leftover from an aborted run
    if (!createVethPair(kA, kB)) {
        GTEST_SKIP() << "veth pair unavailable on this kernel";
    }
    ScopeExit pair_cleanup([&] { deleteIface(kA); });

    const std::uint32_t service_ip = ::inet_addr("172.16.9.2");  // assigned to kA
    const std::uint32_t client_ip = ::inet_addr("172.16.9.9");   // the DUT client's source
    if (!assignIpv4(kA, "172.16.9.2", 24)) {
        GTEST_SKIP() << "could not assign IPv4 (kernel/privilege)";
    }
    // Static neighbor for the client IP so the reply egresses kA immediately
    // rather than waiting on an ARP that nothing would answer (kB has no IP).
    const std::array<std::uint8_t, 6> client_mac{0x02, 0, 0, 0, 0, 0xC9};
    tc8::dut::LinuxSocketBackend backend;
    ASSERT_TRUE(backend.addStaticNeighbor(kA, client_ip, client_mac.data()))
        << "could not install static neighbor";

    // Capture on the PEER end: the reply egresses kA toward the client and crosses
    // the veth to kB, where it arrives as ingress (same topology as the ARP live
    // test). The static neighbor above makes that egress immediate.
    const int cap = openIpCapture(kB);
    ASSERT_GE(cap, 0) << "could not open IP capture on peer iface";
    ScopeExit cap_cleanup([&] { ::close(cap); });

    // Builder: echo the request back as a SOME/IP Response (Message ID + Request
    // ID + payload preserved), the canonical tester-as-server reply.
    auto builder = [](const tc8::stimulus::MethodRequestObservation& req)
        -> std::optional<std::vector<std::uint8_t>> {
        tc8::stimulus::SomeIpRpcMessage t{};
        t.service_id = req.service_id;
        t.method_id = req.method_id;
        t.client_id = req.client_id;
        t.session_id = req.session_id;
        t.payload = req.payload;
        return tc8::stimulus::buildMethodResponse(t);
    };
    tc8::stimulus::MethodResponder responder(kA, kServiceId, kMethodId, kServicePort, builder);
    ASSERT_TRUE(responder.ok());
    ASSERT_GE(responder.pollFd(), 0);

    // Inject the DUT's Method Request on the peer: client_ip:kClientPort ->
    // service_ip:kServicePort. A bogus L2 destination keeps the host kernel from
    // processing it (no ICMP-unreachable noise); the responder's AF_PACKET RX sees
    // it regardless of L2 dst.
    tc8::stimulus::SomeIpRpcMessage req{};
    req.service_id = kServiceId;
    req.method_id = kMethodId;
    req.client_id = 0x1234;
    req.session_id = 0x0005;
    req.payload = {0xAA, 0xBB, 0xCC};
    const std::array<std::uint8_t, 6> bogus_dst{0x02, 0, 0, 0, 0, 0xDD};
    const auto request_frame = tc8::stimulus::buildUdpFromSourceIpFrame(
        tc8::stimulus::buildMethodRequest(req), client_ip, kClientPort, service_ip, kServicePort,
        bogus_dst, client_mac);
    ASSERT_EQ(tc8::stimulus::sendRawEthernet(request_frame, kB), 0);

    // Drive onReadable() (answers the Request) and watch the responder's egress for
    // the SOME/IP Response addressed back to the client.
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
            responder.onReadable();  // read the Request and emit the Response
        }
        if (!(p[1].revents & POLLIN)) {
            continue;
        }
        std::uint8_t buf[256];
        sockaddr_ll from{};
        socklen_t fl = sizeof(from);
        const ssize_t n =
            ::recvfrom(cap, buf, sizeof(buf), 0, reinterpret_cast<sockaddr*>(&from), &fl);
        if (n < 14 + 20 + 8 + 16) {
            continue;
        }
        if (from.sll_pkttype == PACKET_OUTGOING) {
            continue;  // kB's own injected Request echoed on egress — not the reply
        }
        if (tc8::someip::getBe16(buf + 12) != 0x0800 || buf[14 + 9] != 17) {
            continue;  // not IPv4/UDP
        }
        const std::size_t ihl = static_cast<std::size_t>(buf[14] & 0x0F) * 4;
        const std::uint8_t* udp = buf + 14 + ihl;
        if (tc8::someip::getBe16(udp + 0) != kServicePort) {
            continue;  // not from the offered service port (skips the Request itself)
        }
        const std::uint8_t* sip = udp + 8;
        EXPECT_EQ(tc8::someip::getBe16(sip + 0), kServiceId);
        EXPECT_EQ(tc8::someip::getBe16(sip + 2), kMethodId);
        EXPECT_EQ(sip[14], static_cast<std::uint8_t>(tc8::someip::MessageType::RESPONSE));
        EXPECT_EQ(tc8::someip::getBe16(sip + 8), 0x1234);   // Request ID echoed
        EXPECT_EQ(tc8::someip::getBe16(sip + 10), 0x0005);
        EXPECT_EQ(tc8::someip::getBe16(udp + 2), kClientPort);  // back to the client's port
        got_reply = true;
    }

    EXPECT_TRUE(got_reply) << "MethodResponder did not emit a Response";
    // Exactly one reply: the Request is answered once and the responder's own
    // egress Response (seen as PACKET_OUTGOING) is skipped, never re-answered.
    EXPECT_EQ(responder.repliesSent(), 1U);
}

}  // namespace
