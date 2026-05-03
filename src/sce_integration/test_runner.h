#pragma once

#include <chrono>
#include <functional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "tc8/captured_event.h"

#include "test_case_traits.h"
#include "test_config.h"

namespace tc8::sce {

// Stimulus scheduler — opt-in handle that compound-phase traits use to
// emit additional packets AFTER `kickStimulus` returns and the SCXML
// has had time to reach a target state. Replaces the prior
// detached-`std::thread` workaround documented in
// `reference_fragments_compound_stimulus.md`:
//
//   - Old pattern: `std::thread([]{ sleep_for(N); emit(); }).detach()`
//     spawned inside `Traits::stimulus`. Risk surface: SIGKILL race
//     (test reaches verdict early → process exit → thread killed
//     mid-sleep, partial-emit possible); thread leak across the
//     `kickStimulus`→poll-loop boundary; hidden coupling between the
//     trait's sleep and the SCXML deadline.
//   - New pattern: `scheduler.schedule(delay, [...]{ emit(); })`. The
//     poll loop's `tick()` drains due actions inline, so a verdict-
//     reach short-circuits the queue cleanly (the test exits without
//     firing remaining stimulus, no thread to leak), and the action
//     runs on the same thread as `tick()` / `onCaptured` so there is
//     no concurrent capture/emit interleaving.
//
// Cases opt in by adding a 4-arg `stimulus(Captured&, const TestConfig&,
// std::string_view, IStimulusScheduler&)` overload. The 3-arg legacy
// signature continues to work unchanged for the ~110 cases that emit
// purely synchronously inside `kickStimulus`.
class IStimulusScheduler {
public:
    virtual ~IStimulusScheduler() = default;

    // Enqueue `action` to fire after `delay` wall time, measured from
    // the `schedule()` call. Drained inside `ITestRunner::tick()`; the
    // CLI poll loop's 20 ms idle cadence bounds the firing jitter, so
    // delays under ~50 ms should not be expected to be precise.
    // `action` runs on the poll-loop thread, synchronously between
    // pcap drain and `sm_.tick()`. May call `schedule()` itself
    // (e.g. to chain phases) — the implementation defers re-entrant
    // pushes until the current drain finishes, so chained delays
    // accumulate correctly.
    virtual void schedule(std::chrono::milliseconds delay,
                          std::function<void()> action) = 0;

    // Enqueue `action` to fire on the first `tick()` after the SCXML
    // reaches `state_id`. Eliminates the wall-time coupling that
    // `schedule(delay, …)` carries for compound-phase shapes:
    //
    //   - With `schedule(delay, …)`, the trait must encode the SCXML
    //     `<send delay="…"/>` window plus jitter as a magic milliseconds
    //     constant, paired with a "COUPLING NOTE" comment on both sides
    //     because there is no shared C++ source of truth (SCXML delay
    //     attributes take string literals only).
    //   - With `scheduleAfterStateEntry(state_id, …)`, the trait names
    //     the target state symbolically — the runner observes the
    //     transition and fires the action the next time `tick()` runs
    //     after the SM has settled on `state_id`. The SCXML's deadline
    //     stays the deadline (a real timing promise to the spec), and
    //     the trait stops measuring it.
    //
    // `state_id` is `static_cast<int>(SM::PolicyType::State::X)`. The
    // runner casts the SM's current state to `int` for comparison, so
    // the polymorphic interface stays free of the per-case enum type.
    //
    // Firing semantics: the action fires AT MOST ONCE, on the first
    // `tick()` whose end-of-tick `getCurrentState()` differs from the
    // previous tick's and matches `state_id`. The observer is removed
    // after firing; re-registering inside the action is permitted.
    // Registering for the SM's initial state is a no-op (no transition
    // ever lands there from a different state); register for a
    // post-initial state instead.
    virtual void scheduleAfterStateEntry(int state_id,
                                         std::function<void()> action) = 0;
};

// Type-erased handle the CLI uses to drive whichever state machine was
// selected by `--case`. `TestRunner<SM>` is the only implementer; each
// per-case specialization brings its own vtable via the template.
//
// Lifecycle contract:
//   1. Factory constructs the runner and applies configuration.
//   2. `kickStimulus(iface)` — tester-side packet emit (may block).
//      May enqueue scheduled-stimulus actions via `IStimulusScheduler`
//      that fire later from `tick()`.
//   3. `start()` — initializes the state machine. SCXML <send delay=...>
//      timers arm only here, so the listen window begins AFTER any
//      stimulus wall-time. Without this split, a 5 s deadline would
//      shrink by the stimulus's 2.5 s block, making the effective
//      window 2.5 s and sensitive to DUT bootstrap jitter.
//   4. Poll loop: the CLI alternates `onCaptured` (when wire frames
//      arrive) with `tick()` (at every loop iteration, including idle
//      iterations when no frames arrived) until `isDone()` or the
//      harness deadline fires. `tick()` also drains any
//      scheduled-stimulus actions whose deadline has elapsed.
// `isDone()` / `verdict()` / `onCaptured()` must not be called before
// `start()` — behaviour is undefined (the underlying SM has no state).
//
// Event-flow division of labour:
//   - External wire events → `onCaptured` → Traits::dispatch raises the
//     SCXML event and steps the SM synchronously. Immediate feedback.
//   - Scheduled events (W3C SCXML `<send delay="..."/>`) → `tick()`
//     pumps the scheduler into the external queue and steps. Essential
//     for absence-pattern cases (e.g. §4.2.4.1 ARP_03/05) whose pass
//     criterion is "no wire event arrived before the deadline fired" —
//     without the scheduler pump, the `deadline_exceeded` timer sits in
//     the scheduler forever and the SM stays in `listening` indefinitely.
//   - Scheduled stimulus actions (`IStimulusScheduler::schedule`) →
//     `tick()` fires due actions on the poll-loop thread before
//     stepping the SM. Used by compound-phase cases that need a phase
//     to wire AFTER an SCXML absence window has elapsed.
//   - State-entry stimulus actions
//     (`IStimulusScheduler::scheduleAfterStateEntry`) → `tick()`
//     compares the SM's `getCurrentState()` to the previous tick's
//     value and fires registered observers when the SCXML lands on
//     their target state. Same surgical purpose as scheduled actions
//     but driven by SCXML state transitions rather than wall time, so
//     the trait does not have to track the SCXML's deadline as a
//     magic milliseconds constant.
class ITestRunner {
public:
    virtual ~ITestRunner() = default;

    // Optional tester-side packet emit for cases whose TC8 Test Procedure
    // begins with a TESTER-initiated request (e.g. FORMAT_12/13). Called
    // once by the CLI after the capture source has been opened and BPF
    // applied, so the DUT's solicited response falls inside the capture
    // window. `iface` is the same `--interface` the capture is bound to
    // — the stimulus reuses it to pin multicast egress. Cases without a
    // stimulus hook (most of §5.1) get a no-op.
    virtual void kickStimulus(std::string_view iface) = 0;

    // Initializes the underlying state machine. Separate from the ctor
    // so SCXML deadline timers do not arm until after `kickStimulus`
    // completes. Idempotent is not required — callers invoke exactly
    // once between `kickStimulus` and the poll loop.
    virtual void start() = 0;

    // Deliver a wire-captured event to `Traits::dispatch`, which raises
    // the corresponding SCXML event and runs one synchronous macrostep.
    virtual void onCaptured(const ::tc8::CapturedEvent &ev) = 0;

    // Advance the SM one "idle macrostep": pump the scheduler (ready
    // `<send delay="..."/>` events move to the external queue), process
    // the queue, run eventless transitions, fire completion callbacks,
    // and drain any due scheduled-stimulus actions. Called by the CLI
    // every poll iteration even when `onCaptured` did not run, so
    // scheduled events fire at real-time accuracy bounded by the pcap
    // read timeout (~100 ms) and the idle sleep (~20 ms).
    virtual void tick() = 0;

    virtual bool isDone() const = 0;
    virtual std::string_view verdict() const = 0;
};

// Drives an AOT-compiled SCXML state machine for a single TC8 test case.
//
// Per-case behaviour lives in a `TestCaseTraits<SM>` specialization:
//   - `Captured` names the SCE Named Context type the dispatch() writes
//     wire-captured fields into; the SCXML reads them via `cpp:captured.*`.
//   - `Expected` names the sibling Named Context type carrying CLI-injected
//     identity; the SCXML reads it via `cpp:expected.*`. Cases that don't
//     compare against expected values still declare the context so the
//     generated SM constructor has a uniform two-arg shape.
//   - `dispatch(captured, sm, ev)` demultiplexes the CapturedEvent variant,
//     fills the fields it cares about, and raises the appropriate SCXML
//     event(s). Single-protocol cases dispatch on one alternative;
//     cross-protocol cases handle several.
template <typename StateMachine>
class TestRunner final : public ITestRunner, public IStimulusScheduler {
public:
    using Traits = TestCaseTraits<StateMachine>;
    using Captured = typename Traits::Captured;
    using Expected = typename Traits::Expected;
    using State = typename StateMachine::PolicyType::State;

    // Constructor pushes configuration into both contexts so any subsequent
    // stimulus / initial-state <onentry> can observe expected values set
    // via `--expect`. Per-context application is dispatched via ADL on
    // `applyTestConfig(Context&, const TestConfig&)` — each context header
    // provides the overload (captured's is a no-op; expected's copies the
    // flat DTO). State machine initialization is deferred to `start()` so
    // SCXML delay-based deadline timers do not burn wall-time during the
    // tester-side stimulus block.
    explicit TestRunner(const ::tc8::TestConfig &cfg = {})
        : cfg_{cfg}, captured_{}, expected_{}, sm_(captured_, expected_) {
        applyTestConfig(captured_, cfg_);
        applyTestConfig(expected_, cfg_);
    }

    void kickStimulus(std::string_view iface) override {
        // Pin the iface name for any later dispatch path that opted
        // into the 4-arg overload. Held by value (not string_view) so
        // the buffer outlives the kickStimulus caller's string — the
        // CLI hands a temporary, and dispatch may fire arbitrarily
        // later from the poll loop.
        iface_ = std::string(iface);
        if constexpr (has_scheduled_stimulus_v<Traits>) {
            Traits::stimulus(captured_, cfg_, iface,
                             static_cast<IStimulusScheduler &>(*this));
        } else if constexpr (has_stimulus_v<Traits>) {
            Traits::stimulus(captured_, cfg_, iface);
        }
    }

    void start() override {
        sm_.initialize();
        // Anchor the state-entry observer baseline. A transition is
        // detected when `getCurrentState()` differs from this value,
        // so registering for the initial state is intentionally a
        // no-op (the SM is never observed to "enter" it from
        // somewhere else — initialize() lands directly).
        last_state_id_ = static_cast<int>(sm_.getCurrentState());
    }

    void onCaptured(const ::tc8::CapturedEvent &ev) override {
        if constexpr (has_iface_dispatch_v<Traits>) {
            // Cases that emit follow-up stimulus inside dispatch (e.g.
            // §4.5.6.2 ADDRESS_SELECTION_14's self-loop conflict cycle)
            // need the bound interface name. Threaded through by value
            // out of `iface_` so dispatch never depends on a string
            // reference held by the CLI poll loop.
            Traits::dispatch(captured_, sm_, ev, std::string_view{iface_});
        } else {
            Traits::dispatch(captured_, sm_, ev);
        }
    }

    void tick() override {
        drainDueStimulus();

        // Use tick() (not step()) so the SCE scheduler pumps ready timers
        // into the event queue before eventless transitions run. Absence
        // cases like §4.2.4.1 ARP_03/05 rely on a `<send event="..."
        // delay="..."/>` firing inside the listen window — step() alone
        // drains only already-raised events and would leave the timer
        // event stuck in the scheduler until another external event
        // arrives (which never happens in the absence flow).
        sm_.tick();

        // Detect the SCXML having entered any state with registered
        // observers AS A RESULT OF this tick (a `<send delay=…/>`
        // firing into the queue is the most common trigger). Run AFTER
        // `sm_.tick()` so the observer sees the post-step state and
        // fires inside the same poll iteration, not one cadence later.
        drainStateEntryObservers();
    }

    bool isDone() const override {
        return StateMachine::PolicyType::isFinalState(finalState());
    }

    std::string_view verdict() const override {
        return Traits::verdictFor(finalState());
    }

    State finalState() const {
        return sm_.getCurrentState();
    }

    // IStimulusScheduler
    void schedule(std::chrono::milliseconds delay,
                  std::function<void()> action) override {
        stim_queue_.push_back(ScheduledStimulus{
            std::chrono::steady_clock::now() + delay,
            std::move(action),
        });
    }

    void scheduleAfterStateEntry(int state_id,
                                 std::function<void()> action) override {
        state_entry_observers_.push_back(StateEntryObserver{
            state_id,
            std::move(action),
        });
    }

private:
    struct ScheduledStimulus {
        std::chrono::steady_clock::time_point fire_at;
        std::function<void()>                 action;
    };

    struct StateEntryObserver {
        int                   state_id;
        std::function<void()> action;
    };

    // Move every action whose `fire_at` <= now into a local buffer
    // before invoking it. Drained-then-fired (rather than drained-as-
    // fired) so an action that re-enters `schedule()` does not race
    // iterator invalidation on `stim_queue_`. The new action lands at
    // the back of the queue with its own `fire_at` and gets considered
    // on the NEXT `tick()` drain — never within the same drain cycle,
    // which preserves the "delay is measured from schedule() call"
    // contract.
    void drainDueStimulus() {
        if (stim_queue_.empty()) {
            return;
        }
        const auto now = std::chrono::steady_clock::now();
        std::vector<std::function<void()>> due;
        auto it = stim_queue_.begin();
        while (it != stim_queue_.end()) {
            if (it->fire_at <= now) {
                due.push_back(std::move(it->action));
                it = stim_queue_.erase(it);
            } else {
                ++it;
            }
        }
        for (auto &action : due) {
            action();
        }
    }

    // Fires observers whose `state_id` matches the SM's current state,
    // gated on a prior-tick state change so the same observer does not
    // re-fire while the SM lingers. Drained-then-fired (mirrors
    // `drainDueStimulus`) so an action that re-registers via
    // `scheduleAfterStateEntry` lands at the back of the vector and is
    // considered on the NEXT tick — never within the same drain cycle.
    void drainStateEntryObservers() {
        if (state_entry_observers_.empty()) {
            return;
        }
        const int now_id = static_cast<int>(sm_.getCurrentState());
        if (now_id == last_state_id_) {
            return;
        }
        last_state_id_ = now_id;
        std::vector<std::function<void()>> due;
        auto it = state_entry_observers_.begin();
        while (it != state_entry_observers_.end()) {
            if (it->state_id == now_id) {
                due.push_back(std::move(it->action));
                it = state_entry_observers_.erase(it);
            } else {
                ++it;
            }
        }
        for (auto &action : due) {
            action();
        }
    }

    ::tc8::TestConfig                  cfg_;
    Captured                           captured_;
    Expected                           expected_;
    StateMachine                       sm_;
    std::vector<ScheduledStimulus>     stim_queue_;
    std::vector<StateEntryObserver>    state_entry_observers_;
    int                                last_state_id_ = -1;
    std::string                        iface_;
};

}  // namespace tc8::sce
