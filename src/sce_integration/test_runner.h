#pragma once

#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include "tc8/capture_stats.h"
#include "tc8/captured_event.h"
#include "tc8/pollable_service.h"

#include "adopted_services.h"
#include "captured_frame_observer.h"
#include "captured_frame_timing.h"
#include "captured_trace.h"
#include "test_case_traits.h"
#include "test_config.h"
#include "verdict.h"

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

// A run-scoped service owner: a case hands the runner a `tc8::IPollableService`
// via `adoptService` during `stimulus()`, and the runner owns it across the
// capture window (destroying it at teardown) and surfaces it to the CLI capture
// loop via `ITestRunner::pollableServices()`. Segregated from `IStimulusScheduler`
// (which only schedules fire-and-forget actions) so a case depends only on the
// seam it uses. See `tc8/pollable_service.h` for the lifetime rationale.
class IBackgroundServiceOwner {
public:
    virtual ~IBackgroundServiceOwner() = default;

    // Transfer ownership of a pollable service to the runner. Owned for the whole
    // run and destroyed (RAII) at teardown regardless of whether it armed — a
    // service whose `pollFd()` is -1 is simply skipped by the capture loop. A case
    // checks the concrete object's own status before adopting if it needs to
    // surface a failed arm (e.g. as an inconclusive verdict).
    virtual void adoptService(std::unique_ptr<::tc8::IPollableService> service) = 0;

    // Like adoptService, but the service ALSO observes captured frames: the runner
    // owns and polls it exactly as adoptService does AND calls its onCapturedFrame
    // for every CapturedEvent (post-dispatch). The one owned object plays both roles
    // — its own fd is drained by the capture loop, and it reacts to observed wire
    // frames — so a reaction responder can emit on an observed reply instead of a
    // wall-clock settle. The combined IFrameObservingService type registers both
    // roles with no run-time type query.
    virtual void adoptObservingService(
        std::unique_ptr<IFrameObservingService> service) = 0;
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
//   - Frame-observing services
//     (`IBackgroundServiceOwner::adoptObservingService`) → `onCaptured`
//     fans every captured frame out (post-dispatch) to each adopted
//     observer on the same single thread, so a reaction responder can
//     emit on an OBSERVED reply instead of a wall-clock settle.
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
    //
    // `dut_control` is the Tier-2 seam handle (built by the CLI via
    // `makeDutControl` from `--dut-control`), forwarded to cases whose
    // stimulus takes `IDutControl&`. Passed by reference — the CLI always
    // owns exactly one backend for the run, so there is no "no backend"
    // state to model; cases that drive the opcode builders directly ignore
    // it (as they ignore `iface` when they don't emit on it).
    virtual void kickStimulus(std::string_view iface, IDutControl &dut_control) = 0;

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

    // Conformance verdict (class + reason), sourced from the SCXML
    // `<final>`'s `<donedata>` (W3C SCXML 5.5) — see `TestRunner::verdict`.
    // The `Running` sentinel is returned when the SM is not in a
    // donedata-bearing final state. See `verdict.h` for the taxonomy.
    virtual Verdict verdict() const = 0;

    // Evidence Export (Option 3 SSOT): the CLI dispatch callback calls
    // ``setNextPcapFrameIdx`` with the saved-pcap frame index right
    // before each ``pipeline.processFrame`` so a transition fired by
    // the resulting ``onCaptured`` can be correlated back to a packet
    // in the persisted pcap. Set to ``-1`` for frames that are not
    // retained in the saved pcap (no dumper, or pre-filter drop) — any
    // transition recorded while the slot holds -1 is treated as
    // "verdict-decider not retained" by the site walker.
    virtual void setNextPcapFrameIdx(int idx) = 0;

    // Per-source capture accounting for this run, pushed by the CLI at capture
    // teardown (the CLI owns the sources; the runner must not learn libpcap to
    // report a number — same direction as `setNextPcapFrameIdx` above). Rides
    // the trace so a verdict's evidence record states whether the observation
    // underlying it was COMPLETE: a gap measured on a run that dropped frames is
    // short by an unknown amount, and without this the false FAIL and the real
    // violation are indistinguishable even with the pcap in hand.
    //
    // Empty (the default) means no source reported — the trace then says so
    // rather than claiming a clean capture.
    virtual void setCaptureStats(std::vector<::tc8::CaptureStats> stats) = 0;

    // Serialize the recorded transition trace as a JSON object compatible
    // with site/scripts/generate_messages.py's ``captured_trace`` schema.
    // Always returns valid JSON — at minimum
    // ``{"schema_version":2,"final_state":"…","capture":[],"steps":[]}`` for a
    // case that fired no transitions before its deadline.
    //
    // Schema 2 adds the run-level ``capture`` array (see `setCaptureStats`); it
    // is purely additive, so a reader of the schema-1 keys is unaffected, and
    // the version distinguishes "this trace can report capture loss" from an
    // older one that simply could not.
    virtual std::string dumpTraceJson() const = 0;

    // The run-scoped pollable services a case adopted during kickStimulus (via
    // IBackgroundServiceOwner). The CLI capture loop folds each one's pollFd()
    // into its drain set and calls onReadable() each iteration — so a background
    // tester service runs inline on the capture thread, no worker thread. Empty
    // for the vast majority of cases (none adopt a service); the pointers are
    // borrowed and stay valid for the run (the runner retains ownership).
    virtual std::vector<::tc8::IPollableService *> pollableServices() = 0;
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
class TestRunner final : public ITestRunner,
                         public IStimulusScheduler,
                         public IBackgroundServiceOwner {
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
        // A case-local expected default (e.g. an ETS echo payload) is the
        // case's own SSOT for a test-intrinsic expectation. Apply it BEFORE
        // applyTestConfig so a positive run is self-contained (no external
        // value feed needed); applyTestConfig then overrides only the fields
        // `--expect` explicitly set, so the negative harness wins and the
        // conformant default survives the positive run.
        if constexpr (has_expected_defaults_v<Traits>) {
            Traits::applyExpectedDefaults(expected_);
        }
        applyTestConfig(expected_, cfg_);
    }

    void kickStimulus(std::string_view iface, IDutControl &dut_control) override {
        // Pin the iface name for any later dispatch path that opted
        // into the 4-arg overload. Held by value (not string_view) so
        // the buffer outlives the kickStimulus caller's string — the
        // CLI hands a temporary, and dispatch may fire arbitrarily
        // later from the poll loop.
        iface_ = std::string(iface);
        if constexpr (has_dut_scheduled_stimulus_v<Traits>) {
            // Tier-2 seam + scheduler: drive the DUT through the backend
            // selected by `--dut-control` AND let the case enqueue actions
            // that outlive this call (e.g. a deferred tester-side iptables
            // RAII release). Checked first — a 5-arg signature matches
            // neither 4-arg concept below.
            Traits::stimulus(captured_, cfg_, iface, dut_control,
                             static_cast<IStimulusScheduler &>(*this));
        } else if constexpr (has_scheduled_service_owning_stimulus_v<Traits>) {
            // Scheduler + service-owner: the case holds a run-scoped service
            // (e.g. a reliable SubscribeEventgroupTcpSession for a mixed
            // eventgroup) AND enqueues a deferred scheduler action (e.g. a
            // reboot FindService). The runner is both roles; forward both.
            Traits::stimulus(captured_, cfg_, iface,
                             static_cast<IStimulusScheduler &>(*this),
                             static_cast<IBackgroundServiceOwner &>(*this));
        } else if constexpr (has_dut_stimulus_v<Traits>) {
            // Tier-2 seam: drive the DUT through the backend selected by
            // `--dut-control` (opcode UT or AUTOSAR testability).
            Traits::stimulus(captured_, cfg_, iface, dut_control);
        } else if constexpr (has_scheduled_stimulus_v<Traits>) {
            Traits::stimulus(captured_, cfg_, iface,
                             static_cast<IStimulusScheduler &>(*this));
        } else if constexpr (has_service_owning_stimulus_v<Traits>) {
            // The case arms a run-scoped tc8::IPollableService (e.g. an
            // ArpResponder) and hands it to the runner to own across the capture
            // window. Distinct from the scheduler/dut overloads by the 4th param.
            Traits::stimulus(captured_, cfg_, iface,
                             static_cast<IBackgroundServiceOwner &>(*this));
        } else if constexpr (has_stimulus_v<Traits>) {
            Traits::stimulus(captured_, cfg_, iface);
        }
    }

    void start() override {
        sm_.initialize();
        // Stamp the listen-window-open instant — the measurement reference for
        // boot/stimulus-relative timing cases (see
        // `CapturedFrameTiming::delta_from_listen_window_us`). `start()` runs
        // exactly once, after `kickStimulus` returns and before the SM is driven,
        // so this is the listen-window-open time (the kernel BPF capture was
        // armed earlier, before `kickStimulus`). Sampled from `system_clock`
        // (CLOCK_REALTIME / Unix epoch on this platform) to match the pcap
        // `gettimeofday` domain of `observed_ts_us` — NOT `steady_clock`, which
        // the CLI deadline uses and which would make the subtraction meaningless.
        // (A CLOCK_REALTIME step inside the listen window would corrupt the delta;
        // accepted because pcap offers no monotonic stamp and the window is
        // seconds-scale — the same exposure `frame_delta_us()` already carries.)
        // Guarded so a Captured context that does not observe wire timing (no
        // `CapturedFrameTiming` base) still compiles.
        if constexpr (std::is_base_of_v<::tc8::CapturedFrameTiming, Captured>) {
            captured_.listen_window_open_ts_us =
                std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::system_clock::now().time_since_epoch())
                    .count();
        }
        // Anchor the state-entry observer baseline. A transition is
        // detected when `getCurrentState()` differs from this value,
        // so registering for the initial state is intentionally a
        // no-op (the SM is never observed to "enter" it from
        // somewhere else — initialize() lands directly).
        last_state_id_ = static_cast<int>(sm_.getCurrentState());
    }

    void onCaptured(const ::tc8::CapturedEvent &ev) override {
        const State before = sm_.getCurrentState();
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
        const State after = sm_.getCurrentState();
        if (before != after) {
            // Frame-driven transition fired. Record the step before any
            // subsequent `tick()` mutates state further, so a later frame
            // cannot overwrite this step's wire observation.
            //
            // For the wire-derived fields, the post-dispatch values ARE the
            // ground truth the SCXML cond evaluated against: dispatch fills
            // them before `step()` and does not touch them after. That is NOT
            // a general invariant over `captured_`, though — it fails for the
            // fired-transition LANDMARKS, which dispatch rewrites on the way
            // OUT under the very same state-advanced condition that brought us
            // here (`prev_observed_ts_us`, the SOME/IP `prev_sd_session_id` /
            // `prev_tp_more_segments`, the link-local probe pins). A cond read
            // their pre-advance values; by now they hold post-advance ones.
            //
            // Only `prev_observed_ts_us` currently leaks that skew into the
            // trace, because only it feeds a SERIALISED value
            // (`frame_delta_us`) — which is why the trace reads the
            // `fired_frame_delta_us` latch instead of recomputing the accessor
            // (see `appendTimingJson`). The other landmarks are not emitted by
            // any `appendCapturedJson`, so their skew is currently invisible
            // rather than absent. Serialising one, or deriving an emitted
            // value from it, inherits the same trap: latch the pre-advance
            // value in `snapshotFired()` alongside the existing one.
            recordTransition(before, after,
                             /*event_name=*/eventNameForFrame(ev),
                             /*pcap_frame_idx=*/next_pcap_frame_idx_);
        }
        // Do NOT clear ``next_pcap_frame_idx_`` here. One physical pcap
        // frame can fan out into multiple ``CapturedEvent`` sub-events in
        // ``PacketPipeline::processFrame`` (e.g. a TCP packet emits both
        // an ``Ipv4Frame`` and a ``TcpFrame``); a case's dispatch may
        // ignore the first sub-event (no transition) and consume the
        // second (transition fires). Clearing on the first dispatch
        // would mis-attribute the real transition to ``-1`` — the
        // pre-fix bug that left ~99.9% of trace steps null in
        // ICMPv4 / TCP / UDP / SOMEIP* cases. The CLI owns the slot:
        // every physical frame calls ``setNextPcapFrameIdx`` before
        // ``processFrame``, which is the SSOT.

        // Fan the frame out to any adopted frame-observing services AFTER dispatch,
        // so a reaction responder reacts on the post-dispatch ground truth and on
        // this same single thread (no concurrency).
        adopted_.fanOutCapturedFrame(ev);
    }

    void tick() override {
        drainDueStimulus();

        const State before = sm_.getCurrentState();
        // Use tick() (not step()) so the SCE scheduler pumps ready timers
        // into the event queue before eventless transitions run. Absence
        // cases like §4.2.4.1 ARP_03/05 rely on a `<send event="..."
        // delay="..."/>` firing inside the listen window — step() alone
        // drains only already-raised events and would leave the timer
        // event stuck in the scheduler until another external event
        // arrives (which never happens in the absence flow).
        sm_.tick();
        const State after = sm_.getCurrentState();
        if (before != after) {
            // Tick-driven transition — typically a ``deadline_exceeded``
            // timer firing or a scheduled stimulus action that raised an
            // event the SM consumed. No retained pcap frame; record with
            // ``pcap_frame_idx = -1`` so the walker surfaces it as a
            // synthetic verdict-decider note.
            recordTransition(before, after,
                             /*event_name=*/"deadline_exceeded",
                             /*pcap_frame_idx=*/-1);
        }

        // Detect the SCXML having entered any state with registered
        // observers AS A RESULT OF this tick (a `<send delay=…/>`
        // firing into the queue is the most common trigger). Run AFTER
        // `sm_.tick()` so the observer sees the post-step state and
        // fires inside the same poll iteration, not one cadence later.
        drainStateEntryObservers();
    }

    void setNextPcapFrameIdx(int idx) override {
        next_pcap_frame_idx_ = idx;
    }

    void setCaptureStats(std::vector<::tc8::CaptureStats> stats) override {
        capture_stats_ = std::move(stats);
    }

    std::string dumpTraceJson() const override {
        std::string out;
        out.reserve(256 + trace_.size() * 192);
        out.append("{\"schema_version\":2");
        out.append(",\"final_state\":\"");
        ::tc8::sce::appendJsonEscaped(
            out, StateMachine::PolicyType::getStateName(sm_.getCurrentState()));
        // Run-level capture accounting (schema 2). Always emitted — an empty
        // array says "no source reported", which is a different and weaker claim
        // than "nothing was dropped", and the reader must be able to tell.
        // Per-source rather than summed so loss is attributed to the interface
        // that suffered it.
        out.append("\",\"capture\":[");
        for (std::size_t i = 0; i < capture_stats_.size(); ++i) {
            if (i != 0) out.append(",");
            const auto &cs = capture_stats_[i];
            out.append("{\"iface\":\"");
            ::tc8::sce::appendJsonEscaped(out, cs.iface);
            out.append("\",\"available\":");
            out.append(cs.available ? "true" : "false");
            // The counters are emitted ONLY when they mean something. A
            // `frames_dropped_ring: 0` next to `available: false` would invite
            // exactly the misreading this record exists to prevent — an
            // unmeasured capture is not a clean one.
            if (cs.available) {
                ::tc8::sce::appendUintJson(out, ",\"frames_received\":", cs.frames_received);
                ::tc8::sce::appendUintJson(out, ",\"frames_dropped_ring\":", cs.frames_dropped_ring);
                ::tc8::sce::appendUintJson(out, ",\"frames_dropped_iface\":", cs.frames_dropped_iface);
            }
            out.append("}");
        }
        out.append("],\"steps\":[");
        for (std::size_t i = 0; i < trace_.size(); ++i) {
            if (i != 0) out.append(",");
            const auto &s = trace_[i];
            out.append("{\"step\":");
            char buf[32];
            std::snprintf(buf, sizeof(buf), "%d", s.step_idx);
            out.append(buf);
            out.append(",\"event\":\"");
            ::tc8::sce::appendJsonEscaped(out, s.event_name);
            out.append("\",\"from_state\":\"");
            ::tc8::sce::appendJsonEscaped(out, s.from_state_name);
            out.append("\",\"to_state\":\"");
            ::tc8::sce::appendJsonEscaped(out, s.to_state_name);
            out.append("\",\"pcap_frame_idx\":");
            if (s.pcap_frame_idx >= 0) {
                std::snprintf(buf, sizeof(buf), "%d", s.pcap_frame_idx);
                out.append(buf);
            } else {
                out.append("null");
            }
            out.append(",\"captured_delta\":");
            out.append(s.captured_json);
            out.append("}");
        }
        out.append("]}");
        return out;
    }

    bool isDone() const override {
        return StateMachine::PolicyType::isFinalState(finalState());
    }

    Verdict verdict() const override {
        // Verdict SSOT (W3C SCXML 5.5): read back the donedata the generated
        // SM stashed on entry to its `<final>` state (the `<donedata>` authored
        // in the case .scxml, or substituted from its sce:template). This is
        // the single declaration of the verdict — the legacy per-case
        // `verdictFor` switch is retired. Empty donedata (non-final, or a
        // final with no donedata) yields the `Running` sentinel.
        return verdictFromDonedata(sm_.donedataAtFinal());
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

    // IBackgroundServiceOwner — take ownership of a case-armed pollable service.
    void adoptService(std::unique_ptr<::tc8::IPollableService> service) override {
        adopted_.adopt(std::move(service));
    }

    // IBackgroundServiceOwner — own a frame-observing service so it is polled AND
    // notified of every captured frame (see AdoptedServices::adoptObserving).
    void adoptObservingService(std::unique_ptr<IFrameObservingService> service) override {
        adopted_.adoptObserving(std::move(service));
    }

    // ITestRunner — borrow the owned services for the CLI capture loop to poll.
    std::vector<::tc8::IPollableService *> pollableServices() override {
        return adopted_.pollable();
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

    // Resolve the SCXML event id string from a CapturedEvent variant
    // alternative. The mapping mirrors each protocol's per-trait
    // ``raiseExternal(Event::Foo_observed)`` convention (SD/notification
    // cases use ``someip_notification`` instead of ``_observed``);
    // imperatively-raised custom events (e.g. ipv4_linklocal_common's
    // ``spec.conflicts_complete_event``) flow through onCaptured along
    // a frame variant so the recorded name is the FRAME-driven one and
    // not the custom event — the walker tolerates this by relaxing its
    // event-name match (cond_text is still recoverable via from→to
    // pair). Returns an empty string for variant types this build does
    // not know about (defensive — current CapturedEvent has 7
    // alternatives, all mapped below).
    static const char *eventNameForFrame(const ::tc8::CapturedEvent &ev) {
        return std::visit(
            [](const auto &f) -> const char * {
                using T = std::decay_t<decltype(f)>;
                if constexpr (std::is_same_v<T, ::tc8::ArpFrame>)
                    return "arp_observed";
                else if constexpr (std::is_same_v<T, ::tc8::Icmpv4Frame>)
                    return "icmp_observed";
                else if constexpr (std::is_same_v<T, ::tc8::Ipv4Frame>)
                    return "ipv4_observed";
                else if constexpr (std::is_same_v<T, ::tc8::UdpFrame>)
                    return "udp_observed";
                else if constexpr (std::is_same_v<T, ::tc8::Dhcpv4Frame>)
                    return "dhcp_observed";
                else if constexpr (std::is_same_v<T, ::tc8::TcpFrame>)
                    return "tcp_observed";
                else if constexpr (std::is_same_v<T, ::tc8::SomeIpFrame>)
                    return "someip_notification";
                else
                    return "";
            },
            ev);
    }

    void recordTransition(State from, State to, const char *event_name,
                          int pcap_frame_idx) {
        ::tc8::sce::TransitionStep step;
        step.step_idx = static_cast<int>(trace_.size());
        step.event_name = event_name;
        step.from_state_name = StateMachine::PolicyType::getStateName(from);
        step.to_state_name = StateMachine::PolicyType::getStateName(to);
        step.pcap_frame_idx = pcap_frame_idx;
        appendCapturedJson(step.captured_json, captured_);  // ADL
        trace_.push_back(std::move(step));
    }

    ::tc8::TestConfig                  cfg_;
    Captured                           captured_;
    Expected                           expected_;
    StateMachine                       sm_;
    std::vector<ScheduledStimulus>     stim_queue_;
    std::vector<StateEntryObserver>    state_entry_observers_;
    int                                last_state_id_ = -1;
    std::string                        iface_;
    // Evidence Export ledger — appended-to on every state change observed
    // in onCaptured / tick. The walker reads this from the saved pcap's
    // sidecar JSON to render the timeline (single source of truth for
    // verdict-deciding evidence).
    std::vector<::tc8::sce::TransitionStep> trace_;
    // Buffer for the CLI dispatch loop's "the NEXT incoming captured
    // event corresponds to frame index N in the saved pcap" hint. The
    // CLI owns the slot — it calls ``setNextPcapFrameIdx`` before every
    // ``pipeline.processFrame`` (sets the idx for the upcoming physical
    // frame's fan-out of sub-events), and tick() recordTransition calls
    // always hardcode ``-1`` (synthetic / timer-driven). ``onCaptured``
    // only reads it; never resets it.
    int                                next_pcap_frame_idx_ = -1;
    std::vector<::tc8::CaptureStats>   capture_stats_;
    // Run-scoped background services a case adopted (via adoptService /
    // adoptObservingService): owns each pollable, RAII-destroyed here at TestRunner
    // teardown after the capture loop has returned, and fans captured frames out to
    // the observing subset. Declared last so it is destroyed first; the services are
    // self-contained (they hold no reference to sm_/captured_), so teardown order is
    // not load-bearing — last-declared is a conservative default that closes a
    // service's fd before the rest of the runner.
    AdoptedServices adopted_;
};

}  // namespace tc8::sce
