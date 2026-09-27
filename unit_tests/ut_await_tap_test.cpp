// sendUpperTesterRequestAwaited must hear the DUT's reply whatever Ethernet
// destination the DUT chose. Regression for the first on-wire run of the §4.2.3
// static-entry pair: once the DUT's ARP entry for the tester named a MAC that is
// not the tester interface's own (an injected MAC-ADDR1, an installed static
// entry), the DUT sent its acknowledgement there, the tester's kernel dropped it,
// and the awaited request reported "no correlated reply" for a step the capture
// showed applied 0.35 ms later.
//
// A veth pair in a private network namespace stands in for the wire; the far end
// is a fake DUT on an AF_PACKET socket that answers each UT request with a frame
// addressed to a MAC nobody owns. Needs CAP_NET_ADMIN + CAP_NET_RAW, so ctest runs
// it as ut_await_tap_privileged through scripts/run-netns-test.sh; skipped anywhere
// the namespace cannot be had.

#include "stimulus/upper_tester_client.h"

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
#include <cstring>
#include <fstream>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "netns_test_util.h"
#include "stimulus/arp_builder.h"  // sendRawEthernet
#include "stimulus/ipv4_frame_builder.h"
#include "stimulus/udp_datagram_builder.h"
#include "tc8/stimulus_marker.h"
#include "tc8/upper_tester_protocol.h"

namespace tc8::stimulus {
namespace {

namespace ut = ::tc8::ut;

constexpr const char *kTesterIf = "tc8awt0";
constexpr const char *kDutIf = "tc8awd0";
// Owned by neither end of the pair: the MAC-ADDR1 a §4.2 case teaches the DUT.
constexpr std::array<std::uint8_t, 6> kForeignMac{0x02, 0x00, 0x00, 0x00, 0x00, 0xA1};

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

// The far end: answers every UT request it sees on `ifname` with
// <opcode|0x80> <req_id> <status>, Ethernet-addressed to `reply_dst`.
class FakeDut {
public:
    FakeDut(const char *ifname, std::uint32_t dut_ip_be, std::array<std::uint8_t, 6> reply_dst,
            std::uint8_t status, bool corrupt_req_id = false)
        : ifname_(ifname), dut_ip_be_(dut_ip_be), reply_dst_(reply_dst), status_(status),
          corrupt_req_id_(corrupt_req_id) {
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
    ~FakeDut() {
        stop_ = true;
        if (worker_.joinable()) {
            worker_.join();
        }
        if (sk_ >= 0) {
            ::close(sk_);
        }
    }
    bool ok() const { return ok_; }
    // The last reply frame this fake DUT put on the wire — what the capture
    // pipeline would meet as the acknowledgement.
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
            if (n < 14 + 20 + 8 + 2 || from.sll_pkttype == PACKET_OUTGOING) {
                continue;
            }
            const std::uint8_t *ip = buf + 14;
            const std::size_t ihl = static_cast<std::size_t>(ip[0] & 0x0FU) * 4U;
            const std::uint8_t *udp = ip + ihl;
            if (ip[9] != 17 || ((udp[2] << 8) | udp[3]) != ut::kPort) {
                continue;
            }
            std::uint32_t tester_ip_be = 0;
            std::memcpy(&tester_ip_be, ip + 12, 4);
            const auto tester_port = static_cast<std::uint16_t>((udp[0] << 8) | udp[1]);
            const std::uint8_t *req = udp + 8;
            const std::uint8_t reply[3] = {
                static_cast<std::uint8_t>(req[0] | ut::kResponseBit),
                static_cast<std::uint8_t>(corrupt_req_id_ ? req[1] ^ 0xFFU : req[1]), status_};
            Ipv4FrameSpec spec{};
            spec.dst_mac = reply_dst_;
            spec.src_mac = macOf(ifname_);
            spec.src_ip = dut_ip_be_;
            spec.dst_ip = tester_ip_be;
            spec.ip_protocol = 17;
            const auto frame = buildIpv4Frame(
                spec, buildUdpDatagram(dut_ip_be_, tester_ip_be, ut::kPort, tester_port, reply,
                                       sizeof(reply)));
            {
                std::lock_guard<std::mutex> lk(mu_);
                last_reply_ = frame;
            }
            sendRawEthernet(frame, ifname_);
        }
    }

    const char *ifname_;
    std::uint32_t dut_ip_be_;
    std::array<std::uint8_t, 6> reply_dst_;
    std::uint8_t status_;
    bool corrupt_req_id_;
    int sk_ = -1;
    bool ok_ = false;
    std::atomic<bool> stop_{false};
    mutable std::mutex mu_;
    std::vector<std::uint8_t> last_reply_;
    std::thread worker_;
};

// One veth pair for the whole suite, not one per test: the raw-emit path keeps a
// per-thread socket keyed on the interface NAME, so a pair deleted and recreated
// under the same name between tests would leave it bound to a vanished ifindex
// (ENXIO) — a property of reusing names inside one process, not of the wire.
class UtAwaitTap : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        if (!::tc8::testutil::hasNetAdmin() ||
            !::tc8::testutil::createVethPair(kTesterIf, kDutIf)) {
            return;
        }
        ready_ = ::tc8::testutil::assignIpv4(kTesterIf, "10.77.0.1", 24) &&
                 ::tc8::testutil::setIfaceUp(kTesterIf) && ::tc8::testutil::setIfaceUp(kDutIf);
        created_ = true;
    }
    static void TearDownTestSuite() {
        if (created_) {
            ::tc8::testutil::deleteIface(kTesterIf);
        }
    }
    void SetUp() override {
        if (!ready_) {
            GTEST_SKIP() << "needs CAP_NET_ADMIN/CAP_NET_RAW and a veth pair "
                            "(ctest: ut_await_tap_privileged)";
        }
    }
    int send(std::uint8_t opcode) {
        const std::vector<std::uint8_t> req{opcode, nextUtReqId(), 0x00};
        return sendUpperTesterRequestAwaited(kTesterIf, ::inet_addr("10.77.0.1"),
                                             ::inet_addr("10.77.0.2"), macOf(kDutIf),
                                             ut::kTesterSrcPort, req, 1000, "await_tap_test");
    }
    std::uint32_t dutIpBe() const { return ::inet_addr("10.77.0.2"); }

    static inline bool created_ = false;
    static inline bool ready_ = false;
};

// The defect itself: the reply is addressed to a MAC the tester does not own.
TEST_F(UtAwaitTap, HearsAReplyAddressedToAMacTheTesterDoesNotOwn) {
    FakeDut dut(kDutIf, dutIpBe(), kForeignMac, ut::kStatusOk);
    ASSERT_TRUE(dut.ok());
    EXPECT_EQ(send(ut::OpConditionArpCache), 0);
}

// The ordinary case keeps working: the reply reaches the tester's own MAC.
TEST_F(UtAwaitTap, HearsAReplyAddressedToTheTestersOwnMac) {
    FakeDut dut(kDutIf, dutIpBe(), macOf(kTesterIf), ut::kStatusOk);
    ASSERT_TRUE(dut.ok());
    EXPECT_EQ(send(ut::OpConditionArpCache), 0);
}

// A failing status still comes back as the DUT's own answer.
TEST_F(UtAwaitTap, ReturnsTheDutsStatusNotJustLiveness) {
    FakeDut dut(kDutIf, dutIpBe(), kForeignMac, ut::kStatusNotPerformed);
    ASSERT_TRUE(dut.ok());
    EXPECT_EQ(send(ut::OpConditionArpCache), ut::kStatusNotPerformed);
}

// Hearing everything must not mean accepting everything: a reply to some other
// request is not this request's acknowledgement.
TEST_F(UtAwaitTap, AnUncorrelatedReplyIsNotAnAcknowledgement) {
    FakeDut dut(kDutIf, dutIpBe(), kForeignMac, ut::kStatusOk, /*corrupt_req_id=*/true);
    ASSERT_TRUE(dut.ok());
    EXPECT_EQ(send(ut::OpConditionArpCache), -4);
}

// A named, acknowledged step leaves exactly one marker, matched by the very frame
// the DUT sent — what the capture pipeline will meet in order and consume.
TEST_F(UtAwaitTap, AnAcknowledgedStepLeavesOneMarkerForItsAcknowledgement) {
    ::tc8::StimulusMarkers::reset();
    FakeDut dut(kDutIf, dutIpBe(), kForeignMac, ut::kStatusOk);
    ASSERT_TRUE(dut.ok());
    ASSERT_EQ(send(ut::OpConditionArpCache), 0);
    const auto ack = dut.lastReply();
    ASSERT_FALSE(ack.empty());
    EXPECT_EQ(::tc8::StimulusMarkers::take(ack.data(), ack.size()),
              std::optional<std::string>("await_tap_test"));
    EXPECT_EQ(::tc8::StimulusMarkers::take(ack.data(), ack.size()), std::nullopt);
}

// A refused step marks nothing: a case must never open its grading window on a
// precondition the DUT said it did not apply.
TEST_F(UtAwaitTap, ARefusedStepLeavesNoMarker) {
    ::tc8::StimulusMarkers::reset();
    FakeDut dut(kDutIf, dutIpBe(), kForeignMac, ut::kStatusNotPerformed);
    ASSERT_TRUE(dut.ok());
    ASSERT_EQ(send(ut::OpConditionArpCache), ut::kStatusNotPerformed);
    const auto ack = dut.lastReply();
    ASSERT_FALSE(ack.empty());
    EXPECT_EQ(::tc8::StimulusMarkers::take(ack.data(), ack.size()), std::nullopt);
}

// The allocator never hands out 0 and does not repeat within a window of 255.
TEST(UtReqId, NeverZeroAndDistinctAcrossAWindow) {
    std::set<std::uint8_t> seen;
    for (int i = 0; i < 255; ++i) {
        const std::uint8_t id = nextUtReqId();
        EXPECT_NE(id, 0);
        seen.insert(id);
    }
    EXPECT_EQ(seen.size(), 255U);
}

}  // namespace
}  // namespace tc8::stimulus
