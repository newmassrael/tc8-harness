// A live capture source across a link outage (needs CAP_NET_ADMIN and CAP_NET_RAW; run
// under scripts/run-netns-test.sh). RunCapture treats a dispatch that fails while the
// link is down as the outage and keeps polling the same handle; this pins the premise
// that makes that sound: once the link is back up, the handle delivers again without
// being reopened.
#include <arpa/inet.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <thread>

#include <gtest/gtest.h>

#include "capture/pcap_source.h"
#include "netns_test_util.h"
#include "stimulus/arp_builder.h"
#include "tc8/link_outage_tracker.h"
#include "tc8/net/link_control.h"

namespace {

using namespace tc8::testutil;
using namespace std::chrono_literals;

std::uint32_t ipBe(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) {
    return htonl((static_cast<std::uint32_t>(a) << 24) | (static_cast<std::uint32_t>(b) << 16) |
                 (static_cast<std::uint32_t>(c) << 8) | d);
}

bool carriesTraffic(const char *iface) {
    const auto state = tc8::net::readLinkState(iface);
    return state.has_value() && state->admin_up && state->carrier;
}

// Send a frame from `from` until `source` delivers one, for at most `bound`.
bool deliversAFrame(tc8::capture::PcapSource &source, const char *from, std::chrono::milliseconds bound) {
    const auto frame = tc8::stimulus::buildArpRequest({0x02, 0, 0, 0, 0, 0xB0}, ipBe(172, 16, 9, 2),
                                                      ipBe(172, 16, 9, 1));
    const auto deadline = std::chrono::steady_clock::now() + bound;
    while (std::chrono::steady_clock::now() < deadline) {
        tc8::stimulus::sendRawEthernet(frame, from);
        int frames = 0;
        for (int i = 0; i < 10 && frames == 0; ++i) {
            const int n = source.dispatch(-1, [&frames](const pcap_pkthdr &, const u_char *) { ++frames; });
            if (n < 0) {
                break;  // reported below by the caller's next attempt
            }
            std::this_thread::sleep_for(10ms);
        }
        if (frames > 0) {
            return true;
        }
    }
    return false;
}

TEST(CaptureLinkOutage, TheSameHandleDeliversAgainOnceTheLinkIsBack) {
    if (!hasNetAdmin()) {
        GTEST_SKIP() << "needs CAP_NET_ADMIN (run under run-netns-test.sh)";
    }
    constexpr const char *kA = "tc8loa";  // the capture side, whose link goes down
    constexpr const char *kB = "tc8lob";  // the sender
    deleteIface(kA);
    if (!createVethPair(kA, kB)) {
        GTEST_SKIP() << "veth pair unavailable on this kernel";
    }
    ScopeExit pair_cleanup([&] { deleteIface(kA); });
    ASSERT_EQ(tc8::net::awaitCarrier(kA, true, 2s), tc8::net::CarrierWait::kReached);

    std::unique_ptr<tc8::capture::PcapSource> source = tc8::capture::PcapSource::openLive(kA);
    ASSERT_TRUE(source);
    ASSERT_TRUE(deliversAFrame(*source, kB, 3s)) << "no frame before the outage";

    tc8::LinkOutageTracker tracker;
    ASSERT_TRUE(tc8::net::setLinkState(kA, /*up=*/false));
    tracker.observe(carriesTraffic(kA), 1);
    EXPECT_TRUE(tracker.down());
    // While the link is down a dispatch delivers nothing; whether libpcap reports the
    // down link as an error or as no frames, the handle must survive it.
    int frames_while_down = 0;
    for (int i = 0; i < 5; ++i) {
        source->dispatch(-1, [&frames_while_down](const pcap_pkthdr &, const u_char *) { ++frames_while_down; });
        std::this_thread::sleep_for(10ms);
    }
    EXPECT_EQ(frames_while_down, 0);

    ASSERT_TRUE(tc8::net::setLinkState(kA, /*up=*/true));
    ASSERT_EQ(tc8::net::awaitCarrier(kA, true, 2s), tc8::net::CarrierWait::kReached);
    tracker.observe(carriesTraffic(kA), 2);
    EXPECT_FALSE(tracker.down());
    ASSERT_EQ(tracker.outages().size(), 1u);
    EXPECT_EQ(tracker.outages()[0].end_us, 2);

    EXPECT_TRUE(deliversAFrame(*source, kB, 3s)) << "the handle delivered nothing after the link came back";
}

}  // namespace
