#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

// Single emission engine for the OA TC8 v3.0 ETS DUT. There is exactly ONE
// producer per event (no dual-path), fired from one tick thread. Two source
// kinds:
//   - cyclic   : free-running at a fixed period from start() — the legacy
//                unconditional TestEventUINT8 (0x8001) cadence the existing
//                conformance suite depends on. Its payload byte is a counter the
//                controller owns.
//   - triggered: fires ONLY when the EmissionPolicy says so, after a triggerEventX
//                method (TestEventUINT8Array/E2E/Reliable/Multicast). A source that
//                is never triggered never fires — which is what lets the
//                "must-NOT-send" negative cases hold. The policy decides both WHEN
//                it fires and WHICH value it carries.
namespace tc8::dut {

// Canonical emission-source names — the SSOT shared by EtsImpl (which arms a
// source from its triggerEventX Method) and dut_main (which binds each name to
// the matching CommonAPI fireTestEventXEvent). kArray/kReliable/kE2E/kMulticast
// are the OA TC8 v3.0 Table 2 trigger-driven events. kBasic (0x8001) is CYCLIC
// in the public DUT but is registered as a triggered source when an OEM opts in
// via IEtsExtension::ets8001TriggerDriven(); naming it here lets
// EtsImpl::triggerEventUINT8 arm it through the same path as the other four (a
// no-op while it stays cyclic, since the controller skips a due name that has no
// triggered source).
namespace ets_event {
inline constexpr std::string_view kBasic     = "TestEventUINT8";
inline constexpr std::string_view kArray     = "TestEventUINT8Array";
inline constexpr std::string_view kReliable  = "TestEventUINT8Reliable";
inline constexpr std::string_view kE2E       = "TestEventUINT8E2E";
inline constexpr std::string_view kMulticast = "TestEventUINT8Multicast";
}  // namespace ets_event

using EmissionClock = std::chrono::steady_clock;

// The three UInt32 arguments of a triggerEventX method, as they arrived. They are
// handed to the policy unconverted because what one count of each stands for is
// part of the policy's semantics, not of the wire: TC8 §5.1.4 states `start` in
// seconds and leaves `duration` and `debounceTime` without a unit.
struct TriggerArguments {
    std::uint32_t start = 0;
    std::uint32_t duration = 0;
    std::uint32_t debounce_time = 0;
};

// The length one count of each trigger argument stands for.
struct TriggerArgumentUnits {
    std::chrono::milliseconds start = std::chrono::seconds(1);
    std::chrono::milliseconds duration = std::chrono::seconds(1);
    std::chrono::milliseconds debounce_time = std::chrono::milliseconds(1);
};

// This DUT's reading: start and duration in seconds as TC8 states them, and
// debounceTime in milliseconds, the DUT's own choice where TC8 gives no unit.
inline constexpr TriggerArgumentUnits kDutTriggerUnits{};

// One event the policy says is due: which source, and the payload value it carries.
struct Emission {
    std::string source;
    std::uint8_t value = 0;
};

// WHEN each trigger-gated source fires and WITH WHICH VALUE. An extension selects
// a policy through IEtsExtension::makeEmissionPolicy(); the DUT installs it before
// emission starts. Both calls take the caller's `now` so a policy is a pure
// function of its inputs and can be tested without sleeps.
class EmissionPolicy {
public:
    virtual ~EmissionPolicy() = default;
    virtual void onTrigger(std::string_view source, const TriggerArguments& args,
                           EmissionClock::time_point now) = 0;
    // The events due at `now`, in emission order.
    virtual std::vector<Emission> due(EmissionClock::time_point now) = 0;
};

// The DUT's default semantics. After `start`, fire every `debounceTime` while the
// time since the first beat is at most `duration` (the end is inclusive, so a
// zero duration or a zero debounceTime fires one beat). A trigger that arrives
// while a source is armed replaces that arm. Each source's value counts up from 0
// over the whole run and is never reset. A beat missed by a stalled poll is dropped.
class DefaultTriggerPolicy : public EmissionPolicy {
public:
    explicit DefaultTriggerPolicy(TriggerArgumentUnits units = kDutTriggerUnits) : units_(units) {}
    void onTrigger(std::string_view source, const TriggerArguments& args,
                   EmissionClock::time_point now) override;
    std::vector<Emission> due(EmissionClock::time_point now) override;

private:
    struct Arm {
        EmissionClock::time_point next;
        EmissionClock::time_point end;
        std::chrono::milliseconds period;
    };
    TriggerArgumentUnits units_;
    std::mutex mutex_;
    std::unordered_map<std::string, Arm> arms_;
    std::unordered_map<std::string, std::uint8_t> values_;
};

// Triggers that run one after another. For each trigger, per source: the first
// event goes out `start` after the trigger, then one more every `debounceTime`
// while the time since the first event, measured after the debounce wait that
// follows each event, is below `duration` (the end is exclusive; a zero duration
// sends nothing). The values count 1, 2, 3 for each trigger. A trigger that
// arrives while the source's loop is running waits for it, including the
// debounce wait after its last event, and its `start` then counts from there; it
// never replaces the running loop. Each beat keeps its own scheduled time, so a
// late poll emits it late without shifting the next. `zero_debounce` is the cycle
// used for a trigger whose debounceTime is 0.
class SequentialTriggerPolicy : public EmissionPolicy {
public:
    SequentialTriggerPolicy(TriggerArgumentUnits units, std::chrono::milliseconds zero_debounce)
        : units_(units), zero_debounce_(zero_debounce) {}
    void onTrigger(std::string_view source, const TriggerArguments& args,
                   EmissionClock::time_point now) override;
    std::vector<Emission> due(EmissionClock::time_point now) override;

private:
    struct Pending {
        TriggerArguments args;
        EmissionClock::time_point received;
    };
    struct Loop {
        std::deque<Pending> pending;
        bool running = false;
        bool beats_left = false;
        EmissionClock::time_point first_beat{};
        EmissionClock::time_point next_beat{};
        EmissionClock::time_point busy_until{};
        EmissionClock::time_point free_since{};
        EmissionClock::duration duration{};
        EmissionClock::duration period{};
        std::uint8_t value = 1;
    };
    void begin(Loop& loop, const Pending& trigger) const;

    TriggerArgumentUnits units_;
    std::chrono::milliseconds zero_debounce_;
    std::mutex mutex_;
    std::unordered_map<std::string, Loop> loops_;
};

class EmissionController {
public:
    EmissionController();
    ~EmissionController();
    EmissionController(const EmissionController&) = delete;
    EmissionController& operator=(const EmissionController&) = delete;

    // Free-running source: fires every `period` from start(). Add before start().
    void addCyclicSource(std::string name, std::function<void(uint8_t)> emit,
                         std::chrono::milliseconds period);
    // Trigger-gated source: fires only when the policy says so. Add before start().
    void addTriggeredSource(std::string name, std::function<void(uint8_t)> emit);
    // Replace the trigger policy. Must be called before start() (the tick thread
    // reads policy_ locklessly; swapping it live would race). A null policy keeps
    // the current one.
    void installPolicy(std::unique_ptr<EmissionPolicy> policy);
    // Forward a triggerEventX Method call, received now, to the policy.
    void onTrigger(std::string_view source, const TriggerArguments& args);
    void start();
    void stop();

    // One scheduling pass at logical time `now`. run() calls this every tick;
    // exposed so unit tests can drive the engine deterministically (no sleeps).
    void step(EmissionClock::time_point now);

private:
    void run();
    struct Cyclic {
        std::string name;
        std::function<void(uint8_t)> emit;
        std::chrono::milliseconds period;
        EmissionClock::time_point next;
        bool primed = false;
        uint8_t counter = 0;
    };
    std::vector<Cyclic> cyclic_;
    std::unordered_map<std::string, std::function<void(uint8_t)>> triggered_;
    std::unique_ptr<EmissionPolicy> policy_;
    std::thread thread_;
    std::atomic<bool> stop_{false};
};

}  // namespace tc8::dut
