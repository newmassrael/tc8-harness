// Unit tests for the ETS DUT emission engine (dut/dut_service/ets_emission.*).
// The trigger policies are pure logic (functions of an injected `now`), so their
// timing and value branches are tested deterministically with no sleeps.
// EmissionController is driven through its step(now) seam (and a fake policy) so
// source dispatch is deterministic too; one live start()/stop() test covers the
// tick thread.

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
using tc8::dut::Emission;
using tc8::dut::EmissionController;
using tc8::dut::EmissionPolicy;
using tc8::dut::SequentialTriggerPolicy;
using tc8::dut::TriggerArgumentUnits;
using tc8::dut::TriggerArguments;

namespace {

TriggerArguments args(std::uint32_t start, std::uint32_t duration, std::uint32_t debounce) {
    return TriggerArguments{start, duration, debounce};
}

// The values of the events due at each of `times`, for source "X", in order.
std::vector<std::uint8_t> valuesAt(EmissionPolicy& p, Clock::time_point base,
                                   const std::vector<Clock::duration>& times) {
    std::vector<std::uint8_t> values;
    for (const auto t : times) {
        for (const Emission& e : p.due(base + t)) {
            EXPECT_EQ(e.source, "X");
            values.push_back(e.value);
        }
    }
    return values;
}

// Every 100 ms from 0 to `end` inclusive.
std::vector<Clock::duration> every100ms(Clock::duration end) {
    std::vector<Clock::duration> times;
    for (Clock::duration t = 0ms; t <= end; t += 100ms) {
        times.push_back(t);
    }
    return times;
}

// Reads every argument as seconds, as an OEM whose method descriptions say so would.
constexpr TriggerArgumentUnits kAllSeconds{1s, 1s, 1s};

}  // namespace

// --- DefaultTriggerPolicy (the DUT's default semantics) ---

TEST(DefaultTriggerPolicy, NeverTriggeredNeverFires) {
    DefaultTriggerPolicy p;
    EXPECT_TRUE(p.due(Clock::now()).empty());
    EXPECT_TRUE(p.due(Clock::now() + 1h).empty());
}

// Regression for the zero-duration single-shot bug: next == end must still fire
// its one beat, not be erased unfired.
TEST(DefaultTriggerPolicy, ZeroDurationFiresExactlyOnce) {
    DefaultTriggerPolicy p;
    const auto base = Clock::now();
    p.onTrigger("X", args(0, 0, 0), base);
    const auto first = p.due(base + 10ms);
    ASSERT_EQ(first.size(), 1u);
    EXPECT_EQ(first[0].source, "X");
    EXPECT_TRUE(p.due(base + 20ms).empty());  // erased; no repeat
}

// start is seconds (TC8), so 5 means five seconds.
TEST(DefaultTriggerPolicy, StartDelayIsInSeconds) {
    DefaultTriggerPolicy p;
    const auto base = Clock::now();
    p.onTrigger("X", args(5, 0, 0), base);
    EXPECT_TRUE(p.due(base + 4900ms).empty());
    EXPECT_EQ(p.due(base + 5s).size(), 1u);
}

// duration is seconds and debounceTime milliseconds; the end is inclusive, so a
// 1 s window at 100 ms fires at 0, 100, ..., 1000 ms: eleven beats.
TEST(DefaultTriggerPolicy, FiresPerDebounceThroughAnInclusiveEnd) {
    DefaultTriggerPolicy p;
    const auto base = Clock::now();
    p.onTrigger("X", args(0, 1, 100), base);
    EXPECT_EQ(valuesAt(p, base, every100ms(2s)).size(), 11u);
    EXPECT_TRUE(p.due(base + 5s).empty());  // gone, not stuck
}

// The value counts up per source over the whole run: a second trigger continues it.
TEST(DefaultTriggerPolicy, TheValueCountsAcrossTriggersFromZero) {
    DefaultTriggerPolicy p;
    const auto base = Clock::now();
    p.onTrigger("X", args(0, 0, 100), base);
    p.onTrigger("Y", args(0, 0, 100), base);
    const auto first = p.due(base);
    ASSERT_EQ(first.size(), 2u);
    EXPECT_EQ(first[0].value, 0);
    EXPECT_EQ(first[1].value, 0);  // each source has its own count
    p.onTrigger("X", args(0, 0, 100), base + 1s);
    const auto second = p.due(base + 1s);
    ASSERT_EQ(second.size(), 1u);
    EXPECT_EQ(second[0].value, 1);
}

TEST(DefaultTriggerPolicy, ReTriggerReplacesArm) {
    DefaultTriggerPolicy p;
    const auto base = Clock::now();
    p.onTrigger("X", args(100, 0, 0), base);  // far future
    p.onTrigger("X", args(0, 0, 0), base);    // re-trigger: fire now
    EXPECT_EQ(p.due(base + 10ms).size(), 1u);  // second arm wins
}

// The units are the policy's: the same arguments read as seconds wait 1000 times longer.
TEST(DefaultTriggerPolicy, ConstructedUnitsDecideWhatACountMeans) {
    DefaultTriggerPolicy p(kAllSeconds);
    const auto base = Clock::now();
    p.onTrigger("X", args(0, 2, 1), base);
    EXPECT_EQ(valuesAt(p, base, every100ms(3s)), (std::vector<std::uint8_t>{0, 1, 2}));
}

// --- SequentialTriggerPolicy (triggers run one after another) ---

// The first event goes out `start` after the trigger with value 1; one more every
// debounceTime while the time since the first, read after each debounce wait, is
// below duration: 2 s at 1 s gives events at 0 s and 1 s only.
TEST(SequentialTriggerPolicy, CountsFromOneAndEndsExclusively) {
    SequentialTriggerPolicy p(kAllSeconds, 100ms);
    const auto base = Clock::now();
    p.onTrigger("X", args(1, 2, 1), base);
    EXPECT_TRUE(p.due(base + 900ms).empty());
    EXPECT_EQ(valuesAt(p, base, every100ms(5s)), (std::vector<std::uint8_t>{1, 2}));
}

TEST(SequentialTriggerPolicy, AZeroDurationSendsNothing) {
    SequentialTriggerPolicy p(kAllSeconds, 100ms);
    const auto base = Clock::now();
    p.onTrigger("X", args(0, 0, 1), base);
    EXPECT_TRUE(valuesAt(p, base, every100ms(3s)).empty());
}

// A second trigger during the first loop waits for it, including the debounce wait
// after its last event, then starts its own loop at 1 again.
TEST(SequentialTriggerPolicy, ALaterTriggerQueuesBehindTheRunningLoop) {
    SequentialTriggerPolicy p(kAllSeconds, 100ms);
    const auto base = Clock::now();
    p.onTrigger("X", args(0, 2, 1), base);        // events at 0 s, 1 s; busy until 2 s
    p.onTrigger("X", args(0, 1, 1), base + 500ms);  // queued; first event at 2 s
    std::vector<std::pair<Clock::duration, std::uint8_t>> got;
    for (const auto t : every100ms(4s)) {
        for (const Emission& e : p.due(base + t)) {
            got.emplace_back(t, e.value);
        }
    }
    const std::vector<std::pair<Clock::duration, std::uint8_t>> want = {
        {0ms, 1}, {1000ms, 2}, {2000ms, 1}};
    EXPECT_EQ(got, want);
}

// A queued trigger's start counts from when the running loop ended.
TEST(SequentialTriggerPolicy, AQueuedTriggersStartCountsFromTheEndOfTheLoop) {
    SequentialTriggerPolicy p(kAllSeconds, 100ms);
    const auto base = Clock::now();
    p.onTrigger("X", args(0, 1, 1), base);   // event at 0 s; busy until 1 s
    p.onTrigger("X", args(2, 1, 1), base);   // its start: 1 s + 2 s = 3 s
    EXPECT_EQ(valuesAt(p, base, every100ms(2900ms)), (std::vector<std::uint8_t>{1}));
    EXPECT_EQ(valuesAt(p, base, {3s}), (std::vector<std::uint8_t>{1}));
}

// A late poll emits a beat late but does not move the next one.
TEST(SequentialTriggerPolicy, ABeatKeepsItsScheduleAfterALatePoll) {
    SequentialTriggerPolicy p(kAllSeconds, 100ms);
    const auto base = Clock::now();
    p.onTrigger("X", args(0, 3, 1), base);
    EXPECT_EQ(valuesAt(p, base, {0ms, 1500ms}), (std::vector<std::uint8_t>{1, 2}));
    EXPECT_TRUE(p.due(base + 1900ms).empty());
    EXPECT_EQ(valuesAt(p, base, {2s}), (std::vector<std::uint8_t>{3}));
}

TEST(SequentialTriggerPolicy, AZeroDebounceUsesTheConstructedCycle) {
    SequentialTriggerPolicy p(kAllSeconds, 250ms);
    const auto base = Clock::now();
    p.onTrigger("X", args(0, 1, 0), base);
    std::vector<std::uint8_t> values;
    for (Clock::duration t = 0ms; t <= 2s; t += 50ms) {
        for (const Emission& e : p.due(base + t)) {
            values.push_back(e.value);
        }
    }
    EXPECT_EQ(values, (std::vector<std::uint8_t>{1, 2, 3, 4}));  // 0, 250, 500, 750 ms
}

// Each source runs its own loop.
TEST(SequentialTriggerPolicy, SourcesAreIndependent) {
    SequentialTriggerPolicy p(kAllSeconds, 100ms);
    const auto base = Clock::now();
    p.onTrigger("A", args(0, 1, 1), base);
    p.onTrigger("B", args(0, 1, 1), base);
    EXPECT_EQ(p.due(base).size(), 2u);
}

// --- EmissionController (dispatch via step()) ---

namespace {
// Returns a scripted emission list on the first due() call, then nothing.
class FakePolicy : public EmissionPolicy {
public:
    std::vector<Emission> scripted;
    void onTrigger(std::string_view, const TriggerArguments&, Clock::time_point) override {}
    std::vector<Emission> due(Clock::time_point) override {
        std::vector<Emission> r;
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

// The triggered source emits the value the policy chose.
TEST(EmissionController, TriggeredEmitsThePolicysValue) {
    EmissionController c;
    auto fake = std::make_unique<FakePolicy>();
    fake->scripted = {Emission{"T", 7}};
    c.installPolicy(std::move(fake));  // exercises the extension's override seam
    std::vector<uint8_t> got;
    c.addTriggeredSource("T", [&](uint8_t v) { got.push_back(v); });
    c.step(Clock::now());        // policy yields {T, 7}
    c.step(Clock::now() + 1ms);  // policy yields {} -> no fire
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(got[0], 7);
}

TEST(EmissionController, ANullPolicyKeepsTheDefault) {
    EmissionController c;
    c.installPolicy(nullptr);
    std::vector<uint8_t> got;
    c.addTriggeredSource("T", [&](uint8_t v) { got.push_back(v); });
    c.onTrigger("T", args(0, 0, 0));
    c.step(Clock::now() + 10ms);
    EXPECT_EQ(got.size(), 1u);
}

TEST(EmissionController, UnknownDueNameIsIgnored) {
    EmissionController c;
    auto fake = std::make_unique<FakePolicy>();
    fake->scripted = {Emission{"NoSuchSource", 0}};
    c.installPolicy(std::move(fake));
    c.step(Clock::now());  // must not crash with no matching source
    SUCCEED();
}

// OEM mode (IEtsExtension::ets8001TriggerDriven() == true): 0x8001/TestEventUINT8
// is registered as a TRIGGERED source. It must stay silent until triggerEventUINT8
// arms it (via onTrigger(kBasic)), then fire — the contract that makes an OEM's
// must-NOT-send-0x8001 subscribe cases sound. Uses the real DefaultTriggerPolicy
// and the kBasic SSOT name, exactly as EtsImpl + dut_main do.
TEST(EmissionController, BasicTriggerDrivenStaysSilentUntilTriggered) {
    EmissionController c;
    std::vector<uint8_t> got;
    c.addTriggeredSource(std::string(tc8::dut::ets_event::kBasic),
                         [&](uint8_t v) { got.push_back(v); });
    const auto t0 = Clock::now();
    c.step(t0);                                              // no trigger -> silent
    c.step(t0 + 1s);
    EXPECT_TRUE(got.empty());
    c.onTrigger(tc8::dut::ets_event::kBasic, args(0, 0, 0));  // triggerEventUINT8 path
    c.step(Clock::now() + 10ms);                              // armed single shot -> fires once
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(got[0], 0);
}

// Public mode (default): 0x8001 is CYCLIC, yet triggerEventUINT8 still calls
// onTrigger(kBasic) uniformly. Because kBasic is not a triggered source the arm is
// a harmless no-op — only the cyclic cadence fires, with no extra/double beat.
TEST(EmissionController, ArmingTheCyclicBasicNameDoesNotAddBeats) {
    EmissionController c;
    std::vector<uint8_t> got;
    c.addCyclicSource(std::string(tc8::dut::ets_event::kBasic),
                      [&](uint8_t v) { got.push_back(v); }, 100ms);
    const auto t0 = Clock::now();
    c.onTrigger(tc8::dut::ets_event::kBasic, args(0, 0, 0));  // phantom arm (no triggered source)
    c.step(t0);            // prime cyclic; arm find-miss-skipped
    c.step(t0 + 100ms);    // cyclic v=0 only
    c.step(t0 + 200ms);    // cyclic v=1 only
    ASSERT_EQ(got.size(), 2u);
    EXPECT_EQ(got[0], 0);
    EXPECT_EQ(got[1], 1);
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
