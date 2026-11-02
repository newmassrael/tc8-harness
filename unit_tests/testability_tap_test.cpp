// The testability service-primitive call must hear the DUT's answer whatever
// Ethernet destination the DUT chose, and a call that completes a named stimulus step
// must leave that step's marker on the answer.
//
// The scenario both guard is a DUT-control extension installing a static ARP entry
// over the DUT's own primitives: the entry maps the tester's address to a MAC no
// tester interface owns, so from then on every reply is addressed to that MAC,
// starting with the install's own acknowledgement. A kernel-routed exchange never
// hears it, and a step with no marker can never be confirmed to the case.
//
// A veth pair in a private network namespace stands in for the wire; the far end is a
// fake testability DUT on an AF_PACKET socket that answers each request with a
// Response addressed to a MAC nobody owns. Needs CAP_NET_ADMIN + CAP_NET_RAW, so
// ctest runs it as testability_tap_privileged through scripts/run-netns-test.sh;
// skipped anywhere the namespace cannot be had.

#include "sce_integration/dut_control.h"

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "netns_test_util.h"
#include "stimulus/arp_builder.h"  // sendRawEthernet
#include "stimulus/ipv4_frame_builder.h"
#include "stimulus/udp_datagram_builder.h"
#include "stimulus/udp_frame_view.h"
#include "tc8/linux_socket_backend.h"
#include "tc8/stimulus_marker.h"
#include "tc8/stimulus_step_names.h"
#include "tc8/testability_protocol.h"

namespace tc8::sce {
namespace {

namespace tp = ::tc8::testability;

constexpr const char *kTesterIf = "tc8tbt0";
constexpr const char *kDutIf = "tc8tbd0";
constexpr const char *kTesterIp = "10.78.0.1";
constexpr const char *kDutIp = "10.78.0.2";
// Owned by neither end of the pair: the MAC a static entry would point the DUT at.
constexpr std::array<std::uint8_t, 6> kForeignMac{0x02, 0x00, 0x00, 0x00, 0x00, 0xA1};
// A primitive the DUT's owner defines; the numbers mean nothing to the harness.
constexpr std::uint8_t kGid = 0x7E;
constexpr std::uint8_t kPid = 0x01;

std::array<std::uint8_t, 6> macOf(const char *ifname) {
    std::ifstream in(std::string("/sys/class/net/") + ifname + "/address");
    std::string text;
    in >> text;
    std::array<std::uint8_t, 6> mac{};
    unsigned int b[6] = {};
    if (std::sscanf(text.c_str(), "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3], &b[4],
                    &b[5]) == 6) {
        for (int i = 0; i < 6; ++i) {
            mac[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(b[i]);
        }
    }
    return mac;
}

// The far end: answers every testability request it sees on `ifname` with a Response
// to the same service and primitive, result `rid`, Ethernet-addressed to `reply_dst`.
class FakeTestabilityDut {
public:
    FakeTestabilityDut(const char *ifname, std::uint32_t dut_ip_be,
                       std::array<std::uint8_t, 6> reply_dst, std::uint8_t rid)
        : ifname_(ifname), dut_ip_be_(dut_ip_be), reply_dst_(reply_dst), rid_(rid) {
        sk_ = ::socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_IP));
        sockaddr_ll ll{};
        ll.sll_family = AF_PACKET;
        ll.sll_protocol = htons(ETH_P_IP);
        ll.sll_ifindex = static_cast<int>(::if_nametoindex(ifname));
        ok_ = sk_ >= 0 && ::bind(sk_, reinterpret_cast<sockaddr *>(&ll), sizeof(ll)) == 0;
        if (ok_) {
            worker_ = std::thread([this] { run(); });
        }
    }
    ~FakeTestabilityDut() {
        stop_ = true;
        if (worker_.joinable()) {
            worker_.join();
        }
        if (sk_ >= 0) {
            ::close(sk_);
        }
    }
    bool ok() const { return ok_; }
    // The last Response this fake DUT put on the wire — what the capture pipeline
    // would meet as the acknowledgement.
    std::vector<std::uint8_t> lastReply() const {
        std::lock_guard<std::mutex> lk(mu_);
        return last_reply_;
    }

private:
    void run() {
        std::uint8_t buf[2048];
        while (!stop_) {
            pollfd pfd{sk_, POLLIN, 0};
            if (::poll(&pfd, 1, 50) <= 0) {
                continue;
            }
            sockaddr_ll from{};
            socklen_t fl = sizeof(from);
            const ssize_t n =
                ::recvfrom(sk_, buf, sizeof(buf), 0, reinterpret_cast<sockaddr *>(&from), &fl);
            if (n <= 0 || from.sll_pkttype == PACKET_OUTGOING) {
                continue;
            }
            const auto v = stimulus::viewUdpFrame(buf, static_cast<std::size_t>(n));
            if (!v || v->dst_ip_be != dut_ip_be_ || v->dst_port != tp::kDefaultPort) {
                continue;
            }
            const auto req = tp::parseHeader(v->payload, v->payload_len);
            if (!req || req->tid != tp::kTidRequest) {
                continue;
            }
            tp::Header h;
            h.service_id = req->service_id;
            h.method_id = req->method_id;
            h.tid = tp::kTidResponse;
            h.rid = rid_;
            const auto resp = tp::buildMessage(h, nullptr, 0);
            stimulus::Ipv4FrameSpec spec{};
            spec.dst_mac = reply_dst_;
            spec.src_mac = macOf(ifname_);
            spec.src_ip = dut_ip_be_;
            spec.dst_ip = v->src_ip_be;
            spec.ip_protocol = 17;
            const auto frame = stimulus::buildIpv4Frame(
                spec, stimulus::buildUdpDatagram(dut_ip_be_, v->src_ip_be, tp::kDefaultPort,
                                                 v->src_port, resp.data(), resp.size()));
            {
                std::lock_guard<std::mutex> lk(mu_);
                last_reply_ = frame;
            }
            stimulus::sendRawEthernet(frame, ifname_);
        }
    }

    const char *ifname_;
    std::uint32_t dut_ip_be_;
    std::array<std::uint8_t, 6> reply_dst_;
    std::uint8_t rid_;
    int sk_ = -1;
    bool ok_ = false;
    std::atomic<bool> stop_{false};
    mutable std::mutex mu_;
    std::vector<std::uint8_t> last_reply_;
    std::thread worker_;
};

// One veth pair for the whole suite (see ut_await_tap_test.cpp for why names must not
// be recreated inside one process). The tester pins the DUT's MAC, so the kernel-routed
// control below reaches the DUT without an ARP exchange and fails only on the reply.
class TestabilityTap : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        if (!::tc8::testutil::hasNetAdmin() ||
            !::tc8::testutil::createVethPair(kTesterIf, kDutIf)) {
            return;
        }
        created_ = true;
        ::tc8::dut::LinuxSocketBackend be;
        const auto dut_mac = macOf(kDutIf);
        ready_ = ::tc8::testutil::assignIpv4(kTesterIf, kTesterIp, 24) &&
                 ::tc8::testutil::setIfaceUp(kTesterIf) && ::tc8::testutil::setIfaceUp(kDutIf) &&
                 be.addStaticNeighbor(kTesterIf, ::inet_addr(kDutIp), dut_mac.data()) ==
                     ::tc8::net::OpStatus::Ok;
    }
    static void TearDownTestSuite() {
        if (created_) {
            ::tc8::testutil::deleteIface(kTesterIf);
        }
    }
    void SetUp() override {
        if (!ready_) {
            GTEST_SKIP() << "needs CAP_NET_ADMIN/CAP_NET_RAW and a veth pair "
                            "(ctest: testability_tap_privileged)";
        }
        ::tc8::StimulusMarkers::reset();
    }

    static tp::TestabilityConfig config() {
        tp::TestabilityConfig cfg;
        cfg.dut_ip_be = ::inet_addr(kDutIp);
        return cfg;
    }
    // The backend as the factory builds it on a run with a wire.
    static std::unique_ptr<TestabilityControl> wired() {
        RawTransport raw;
        raw.iface = kTesterIf;
        raw.tester_ip_be = ::inet_addr(kTesterIp);
        raw.dut_mac = macOf(kDutIf);
        return std::make_unique<TestabilityControl>(config(), /*timeout_ms=*/1000,
                                                    /*src_ip_be=*/0, raw);
    }

    static inline bool created_ = false;
    static inline bool ready_ = false;
};

// The defect: the answer is addressed to a MAC the tester does not own.
TEST_F(TestabilityTap, AWiredPrimitiveCallHearsAnAnswerToAMacTheTesterDoesNotOwn) {
    FakeTestabilityDut dut(kDutIf, ::inet_addr(kDutIp), kForeignMac, tp::kRidEOk);
    ASSERT_TRUE(dut.ok());
    auto backend = wired();
    const DutPrimitiveReply reply = backend->servicePrimitiveControl()->call(kGid, kPid, {});
    EXPECT_TRUE(reply.succeeded());
}

// The negative control, same fake DUT: a kernel-routed call does not hear it. Without
// this the test above could pass on a fake that answered the tester's own MAC.
TEST_F(TestabilityTap, AKernelRoutedPrimitiveCallDoesNotHearIt) {
    FakeTestabilityDut dut(kDutIf, ::inet_addr(kDutIp), kForeignMac, tp::kRidEOk);
    ASSERT_TRUE(dut.ok());
    TestabilityControl unwired(config(), /*timeout_ms=*/300);
    const DutPrimitiveReply reply = unwired.servicePrimitiveControl()->call(kGid, kPid, {});
    EXPECT_FALSE(reply.answered());
}

// A confirmed step leaves exactly one marker, matched by the very frame the DUT sent.
TEST_F(TestabilityTap, AConfirmedStepLeavesOneMarkerOnItsAcknowledgement) {
    FakeTestabilityDut dut(kDutIf, ::inet_addr(kDutIp), kForeignMac, tp::kRidEOk);
    ASSERT_TRUE(dut.ok());
    auto backend = wired();
    const DutPrimitiveReply reply = backend->servicePrimitiveControl()->callAsStep(
        ::tc8::step::kArpStaticEntryAdd, kGid, kPid, {});
    ASSERT_TRUE(reply.succeeded());
    const auto ack = dut.lastReply();
    ASSERT_FALSE(ack.empty());
    EXPECT_EQ(::tc8::StimulusMarkers::take(ack.data(), ack.size()),
              std::optional<std::string>(::tc8::step::kArpStaticEntryAdd));
    EXPECT_EQ(::tc8::StimulusMarkers::take(ack.data(), ack.size()), std::nullopt);
}

// A refused step marks nothing: a case must never open its window on a precondition the
// DUT said it did not apply.
TEST_F(TestabilityTap, ARefusedStepLeavesNoMarker) {
    FakeTestabilityDut dut(kDutIf, ::inet_addr(kDutIp), kForeignMac, tp::kRidENok);
    ASSERT_TRUE(dut.ok());
    auto backend = wired();
    const DutPrimitiveReply reply = backend->servicePrimitiveControl()->callAsStep(
        ::tc8::step::kArpStaticEntryAdd, kGid, kPid, {});
    ASSERT_TRUE(reply.answered());
    EXPECT_FALSE(reply.succeeded());
    const auto ack = dut.lastReply();
    ASSERT_FALSE(ack.empty());
    EXPECT_EQ(::tc8::StimulusMarkers::take(ack.data(), ack.size()), std::nullopt);
}

}  // namespace
}  // namespace tc8::sce
