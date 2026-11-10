// Link outages of a capture source: the tracker that turns link observations into
// intervals, the completeness claim that an outage inside the listen window defeats,
// and the timer that brings a bounced tester link back up (sce_integration/tester_link.h).
#include <chrono>
#include <cstdint>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "sce_integration/tester_link.h"
#include "tc8/capture_stats.h"
#include "tc8/link_outage_tracker.h"
#include "tc8/unperformed_stimulus.h"

namespace {

using namespace std::chrono_literals;

TEST(LinkOutageTracker, OneIntervalPerDownAndUp) {
    tc8::LinkOutageTracker t;
    t.observe(true, 100);
    EXPECT_TRUE(t.outages().empty());
    t.observe(false, 200);
    t.observe(false, 250);  // still down: the same interval
    EXPECT_TRUE(t.down());
    ASSERT_EQ(t.outages().size(), 1u);
    EXPECT_EQ(t.outages()[0].begin_us, 200);
    EXPECT_EQ(t.outages()[0].end_us, 0);  // open
    t.observe(true, 900);
    EXPECT_FALSE(t.down());
    EXPECT_EQ(t.outages()[0].end_us, 900);
    t.observe(false, 1000);
    EXPECT_EQ(t.outages().size(), 2u);
}

tc8::CaptureStats measured() {
    tc8::CaptureStats s;
    s.iface = "veth-tester";
    s.available = true;
    return s;
}

// An outage that ended before the window opened hides nothing the window grades.
TEST(CaptureProvenComplete, AnOutageBeforeTheWindowDoesNotCount) {
    auto s = measured();
    s.link_outages = {tc8::LinkOutage{100, 200}};
    EXPECT_TRUE(tc8::captureProvenComplete({s}, /*window_open_us=*/300));
    EXPECT_FALSE(tc8::captureProvenComplete({s}));  // the default counts the whole run
}

TEST(CaptureProvenComplete, AnOutageInsideTheWindowDefeatsTheClaim) {
    auto s = measured();
    s.link_outages = {tc8::LinkOutage{400, 500}};
    EXPECT_FALSE(tc8::captureProvenComplete({s}, 300));
    // Begun before the window and ended inside it.
    s.link_outages = {tc8::LinkOutage{100, 350}};
    EXPECT_FALSE(tc8::captureProvenComplete({s}, 300));
    // Still down when the capture ended.
    s.link_outages = {tc8::LinkOutage{100, 0}};
    EXPECT_FALSE(tc8::captureProvenComplete({s}, 300));
    EXPECT_TRUE(tc8::anySourceLinkDownSince({s}, 300));
}

struct FakeLink {
    std::vector<bool> calls;
    bool accept = true;
    std::function<bool(bool)> setter() {
        return [this](bool up) {
            calls.push_back(up);
            return accept;
        };
    }
};

TEST(LinkRestoreTimer, RestoresOnceWhenTheDeadlinePasses) {
    tc8::UnperformedStimulus::reset();
    FakeLink link;
    tc8::sce::LinkRestoreTimer timer(link.setter());
    ASSERT_TRUE(timer.valid());
    EXPECT_EQ(timer.pollFd(), -1);  // disarmed: nothing to poll
    ASSERT_TRUE(timer.arm(30ms));
    EXPECT_GE(timer.pollFd(), 0);
    timer.onReadable();  // before the deadline
    EXPECT_TRUE(link.calls.empty());
    std::this_thread::sleep_for(60ms);
    timer.onReadable();
    ASSERT_EQ(link.calls, (std::vector<bool>{true}));
    EXPECT_TRUE(timer.restored());
    EXPECT_EQ(timer.pollFd(), -1);
    timer.onReadable();
    EXPECT_EQ(link.calls.size(), 1u);
    EXPECT_FALSE(tc8::UnperformedStimulus::any());
}

// The run ended before the deadline: the link is restored all the same.
TEST(LinkRestoreTimer, AnArmedTimerRestoresWhenDestroyed) {
    FakeLink link;
    {
        tc8::sce::LinkRestoreTimer timer(link.setter());
        ASSERT_TRUE(timer.arm(10s));
    }
    EXPECT_EQ(link.calls, (std::vector<bool>{true}));
}

TEST(LinkRestoreTimer, ADisarmedTimerLeavesTheLinkAlone) {
    FakeLink link;
    { tc8::sce::LinkRestoreTimer timer(link.setter()); }
    EXPECT_TRUE(link.calls.empty());
}

// A refused restore is the premise of the rest of the run gone: recorded as unperformed.
TEST(LinkRestoreTimer, ARefusedRestoreIsAnUnperformedStimulus) {
    tc8::UnperformedStimulus::reset();
    FakeLink link;
    link.accept = false;
    {
        tc8::sce::LinkRestoreTimer timer(link.setter());
        ASSERT_TRUE(timer.arm(1ms));
        std::this_thread::sleep_for(10ms);
        timer.onReadable();
    }
    EXPECT_TRUE(tc8::UnperformedStimulus::any());
    EXPECT_NE(tc8::UnperformedStimulus::reason().find(tc8::sce::kTesterLinkUpStimulus), std::string::npos);
    tc8::UnperformedStimulus::reset();
}

}  // namespace
