// Unit tests for the ETS DUT emission engine (dut/dut_service/ets_emission.*).
// DefaultTriggerPolicy is pure logic (a function of an injected `now`), so its
// timing branches are tested deterministically with no sleeps. EmissionController
// is driven through its step(now) seam (and a fake policy) so source dispatch and
// the controller-owned payload counters are deterministic too; one live
// start()/stop() test covers the tick thread.

#include "ets_emission.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

using namespace std::chrono_literals;
using Clock = std::chrono::steady_clock;
using tc8::dut::DefaultTriggerPolicy;
using tc8::dut::EmissionController;
using tc8::dut::EmissionPolicy;

// --- DefaultTriggerPolicy (pure timing logic) ---

TEST(DefaultTriggerPolicy, NeverTriggeredNeverFires) {
    DefaultTriggerPolicy p;
    EXPECT_TRUE(p.due(Clock::now()).empty());
    EXPECT_TRUE(p.due(Clock::now() + 1h).empty());
}

// Regression for the zero-duration single-shot bug: next == end must still fire
// its one beat, not be erased unfired.
TEST(DefaultTriggerPolicy, ZeroDurationFiresExactlyOnce) {
    DefaultTriggerPolicy p;
    p.onTrigger("X", 0s, 0s, 0ms);
    const auto base = Clock::now();
    const auto first = p.due(base + 10ms);
    ASSERT_EQ(first.size(), 1u);
    EXPECT_EQ(first[0], "X");
    EXPECT_TRUE(p.due(base + 20ms).empty());  // erased; no repeat
}

TEST(DefaultTriggerPolicy, StartDelayHoldsUntilDue) {
    DefaultTriggerPolicy p;
    p.onTrigger("X", 5s, 0s, 0ms);
    const auto base = Clock::now();
    EXPECT_TRUE(p.due(base + 1s).empty());     // before start delay
    EXPECT_EQ(p.due(base + 6s).size(), 1u);    // after start delay
}

TEST(DefaultTriggerPolicy, PeriodicFiresPerPeriodWithinWindow) {
    DefaultTriggerPolicy p;
    p.onTrigger("X", 0s, 10s, 100ms);
    const auto base = Clock::now();
    int count = 0;
    for (int i = 0; i <= 5; ++i) {
        count += static_cast<int>(p.due(base + i * 100ms).size());
    }
    EXPECT_GE(count, 5);  // ~6 beats over the polled window
}

TEST(DefaultTriggerPolicy, WindowEndStopsAndErases) {
    DefaultTriggerPolicy p;
    p.onTrigger("X", 0s, 1s, 100ms);
    const auto base = Clock::now();
    for (int i = 0; i <= 15; ++i) {
        p.due(base + i * 100ms);  // drain past the 1 s window
    }
    EXPECT_TRUE(p.due(base + 5s).empty());  // gone, not stuck
}

TEST(DefaultTriggerPolicy, ReTriggerReplacesArm) {
    DefaultTriggerPolicy p;
    p.onTrigger("X", 100s, 0s, 0ms);  // far future
    p.onTrigger("X", 0s, 0s, 0ms);    // re-trigger: fire now
    const auto base = Clock::now();
    EXPECT_EQ(p.due(base + 10ms).size(), 1u);  // second arm wins
}

// --- EmissionController (dispatch + owned counters, via step()) ---

namespace {
// Returns a scripted source list on the first due() call, then nothing.
class FakePolicy : public EmissionPolicy {
public:
    std::vector<std::string> scripted;
    void onTrigger(std::string_view, std::chrono::seconds, std::chrono::seconds,
                   std::chrono::milliseconds) override {}
    std::vector<std::string> due(Clock::time_point) override {
        if (scripted.empty()) {
            return {};
        }
        std::vector<std::string> r;
        r.swap(scripted);
        return r;
    }
};
}  // namespace

TEST(EmissionController, CyclicFiresEachPeriodWithOwnedCounter) {
    EmissionController c;
    std::vector<uint8_t> got;
    c.addCyclicSource("C", [&](uint8_t v) { got.push_back(v); }, 100ms);
    const auto t0 = Clock::now();
    c.step(t0);            // primes; no fire
    EXPECT_TRUE(got.empty());
    c.step(t0 + 100ms);    // v = 0
    c.step(t0 + 200ms);    // v = 1
    c.step(t0 + 250ms);    // not due (next is t0+300ms)
    ASSERT_EQ(got.size(), 2u);
    EXPECT_EQ(got[0], 0);
    EXPECT_EQ(got[1], 1);  // controller-owned monotonic counter, no static
}

TEST(EmissionController, TriggeredDispatchesViaInstalledPolicy) {
    EmissionController c;
    auto fake = std::make_unique<FakePolicy>();
    fake->scripted = {"T"};
    c.installPolicy(std::move(fake));  // exercises the OEM override seam
    std::vector<uint8_t> got;
    c.addTriggeredSource("T", [&](uint8_t v) { got.push_back(v); });
    c.step(Clock::now());        // policy yields {"T"} -> fire v=0
    c.step(Clock::now() + 1ms);  // policy yields {} -> no fire
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(got[0], 0);
}

TEST(EmissionController, UnknownDueNameIsIgnored) {
    EmissionController c;
    auto fake = std::make_unique<FakePolicy>();
    fake->scripted = {"NoSuchSource"};
    c.installPolicy(std::move(fake));
    c.step(Clock::now());  // must not crash with no matching source
    SUCCEED();
}

TEST(EmissionController, StartStopRunsTickThread) {
    EmissionController c;
    std::atomic<int> fires{0};
    c.addCyclicSource("C", [&](uint8_t) { fires.fetch_add(1); }, 10ms);
    c.start();
    std::this_thread::sleep_for(120ms);
    c.stop();
    EXPECT_GE(fires.load(), 3);  // ~11 beats; tolerant of scheduling jitter
}
