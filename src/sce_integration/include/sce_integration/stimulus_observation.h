#pragma once

#include <chrono>
#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "tc8/captured_event.h"

#include "owned_captured_event.h"

namespace tc8::sce {

// --- Awaiting an observation from inside a stimulus ---------------------------
//
// A stimulus runs before the listen window opens (`ITestRunner::kickStimulus`,
// then `start()`), and until now nothing drained the capture while it ran: every
// frame the DUT emitted during the stimulus sat in the kernel ring and reached the
// state machine only after the stimulus returned. That ordering is deliberate —
// the SCXML's deadlines arm at `start()`, so the stimulus's own wall time is not
// charged against them — but it left a stimulus with one tool for "the DUT has
// done X, now do Y": a fixed sleep, whose length is a guess about when X happens.
//
// This is the other tool. A stimulus can wait for the capture to show it X, and
// the fixed duration survives only as an upper BOUND on how long it will wait.
// The capture it waits on is the case's own capture — the same filter, the same
// ring, the same saved pcap — not a second tap that could disagree with it about
// what was on the wire.
//
// Two properties are what make it safe to add underneath existing cases:
//
//   - Nothing reaches the state machine early. Frames drained while a stimulus
//     waits are HELD, in capture order and with their saved-pcap index, and are
//     delivered to the state machine at `start()` exactly as the first loop
//     iteration would have delivered them from the ring. A case that awaits
//     grades the same frame sequence it graded when it slept.
//   - A wait that is not satisfied is not a silent fall-through. It is recorded as
//     an unperformed stimulus under the wait's name (tc8/unperformed_stimulus.h),
//     which reaches the report as `inconclusive:stimulus_<name>_not_performed` —
//     the precondition the stimulus depended on did not happen, so the verdict is
//     not about the DUT.

// Delivers the frames the capture holds to the runner, on the calling thread.
// Implemented by the CLI, which owns the capture sources, the saved pcap and the
// packet pipeline; a frame drained here goes through exactly the path a frame
// drained by the capture loop goes through.
class ICapturePump {
public:
    virtual ~ICapturePump() = default;

    enum class Status {
        kOk,            // drained whatever was there (possibly nothing)
        kEndOfCapture,  // an offline source has no more frames
        kError,         // a capture source failed; the capture loop will report it
        kStopped,       // the run was interrupted
    };

    struct Drained {
        Status      status = Status::kOk;
        std::size_t frames = 0;
    };

    // Dispatch every frame the capture holds now, and service the run's pollable
    // background services, without blocking.
    virtual Drained drain() = 0;

    // Block until a capture source or a background service has input, or `max`
    // elapses — whichever is first.
    virtual void waitForInput(std::chrono::milliseconds max) = 0;
};

using ObservationPredicate = std::function<bool(const ::tc8::CapturedEvent &)>;

// A position in the capture: an await from it considers only frames captured
// after the cursor was taken. Opaque to cases.
struct ObservationCursor {
    std::size_t position = 0;
};

// What a stimulus sees of the facility. Reached through `StimulusContext`.
class IStimulusObserver {
public:
    virtual ~IStimulusObserver() = default;

    // Mark "now" in the capture. Everything already captured is drained first and
    // falls BEFORE the cursor, so a frame the DUT sent before this point cannot
    // satisfy a later await from it.
    //
    // Take the cursor BEFORE the step that provokes the frame. A frame the DUT
    // answers with while that step is still running (a blocking emit, a UT round
    // trip) then still counts, which it would not if the wait began afterwards.
    virtual ObservationCursor mark() = 0;

    // Wait until a frame captured after `from` satisfies `predicate`, and return
    // it (owning its bytes; see OwnedCapturedEvent). `bound` is how long to wait
    // from this call.
    //
    // nullopt when it is not seen — the bound elapsed, the capture ended, or the
    // capture failed; each is recorded as an unperformed stimulus named `name`,
    // except an interrupted run, whose own verdict (error) already outranks it.
    //
    // Call it only from the stimulus: once the listen window opens the state
    // machine is live and a frame cannot be held back from it, so a call after
    // the stimulus returns aborts.
    virtual std::optional<OwnedCapturedEvent> awaitObservation(
        std::string_view name, ObservationCursor from, const ObservationPredicate &predicate,
        std::chrono::milliseconds bound) = 0;

    // `awaitObservation` from a cursor taken now: for a frame the DUT sends of its
    // own accord, with nothing the stimulus does in between.
    std::optional<OwnedCapturedEvent> awaitObservation(
        std::string_view name, const ObservationPredicate &predicate,
        std::chrono::milliseconds bound) {
        return awaitObservation(name, mark(), predicate, bound);
    }
};

// --- Reacting to an observation once the listen window is open ---------------
//
// The awaiting half above serves a stimulus that runs BEFORE the window. A step
// scheduled INTO the window (IStimulusScheduler) cannot block the same way: the
// capture it would drain is the one feeding the live state machine, and every
// frame it read would have to reach the machine anyway, in order, while the
// machine's own deadlines ran. So a scheduled step does not wait — it REACTS. It
// registers "when the capture delivers a frame satisfying this, do that", the
// capture loop delivers every frame to the state machine as usual and then to the
// pending reactions, and a reaction whose bound elapses first is recorded as an
// unperformed stimulus under its name, exactly as an unmet wait is.
//
// Register the reaction BEFORE the step that provokes the frame. A frame the DUT
// sends while that step is still running is delivered afterwards, in order, and
// the reaction sees it.
class ObservationReactions {
public:
    using Clock = std::function<std::chrono::steady_clock::time_point()>;
    // Runs on the capture-loop thread with the matching frame. The frame is a view
    // valid for the call only; keep an OwnedCapturedEvent of it to hold it longer.
    using Action = std::function<void(const ::tc8::CapturedEvent &)>;

    explicit ObservationReactions(Clock clock = &std::chrono::steady_clock::now);

    void add(std::string_view name, ObservationPredicate predicate,
             std::chrono::milliseconds bound, Action action);

    // Offer one delivered frame to every pending reaction; each one it satisfies
    // fires, once, and is removed. Collected before firing, so an action that
    // registers a further reaction does not see this same frame.
    void onFrame(const ::tc8::CapturedEvent &ev, int pcap_frame_idx);

    // Record every reaction whose bound has elapsed as an unperformed stimulus.
    void expire();

    bool empty() const {
        return pending_.empty();
    }

private:
    struct Pending {
        std::string                           name;
        ObservationPredicate                  predicate;
        std::chrono::steady_clock::time_point registered;
        std::chrono::steady_clock::time_point deadline;
        Action                                action;
    };

    Clock                clock_;
    std::vector<Pending> pending_;
};

// The held capture and the waits over it. Not a template, so the rules live in
// one tested place; `TestRunner<SM>` holds one and forwards to it.
class StimulusObservation final : public IStimulusObserver {
public:
    using Clock = std::function<std::chrono::steady_clock::time_point()>;

    // A stimulus marker (tc8/stimulus_marker.h) drained during the stimulus — held
    // alongside the frames, since its meaning is its position among them.
    struct Marker {
        std::string name;
    };

    struct Held {
        std::variant<OwnedCapturedEvent, Marker> item;
        int pcap_frame_idx = -1;
    };

    explicit StimulusObservation(Clock clock = &std::chrono::steady_clock::now);

    // The pump is bound for the duration of the stimulus and unbound after it.
    // An await with no pump bound is a call from outside the stimulus.
    void bindPump(ICapturePump *pump) {
        pump_ = pump;
    }

    // Record a frame drained before the listen window opened.
    void hold(const ::tc8::CapturedEvent &ev, int pcap_frame_idx);
    void holdMarker(std::string_view name, int pcap_frame_idx);

    // Hand every held item to `sink` in capture order and forget them.
    void release(const std::function<void(const Held &)> &sink);

    std::size_t heldCount() const {
        return held_.size();
    }

    ObservationCursor mark() override;
    using IStimulusObserver::awaitObservation;
    std::optional<OwnedCapturedEvent> awaitObservation(
        std::string_view name, ObservationCursor from, const ObservationPredicate &predicate,
        std::chrono::milliseconds bound) override;

private:
    // Scan held frames in [position, end) for the first one `predicate` accepts;
    // advances `position` to the end either way.
    const ::tc8::CapturedEvent *scan(std::size_t &position,
                                     const ObservationPredicate &predicate) const;

    // Aborts with the facility's misuse message when no pump is bound.
    void requirePump(std::string_view name) const;

    Clock              clock_;
    ICapturePump      *pump_ = nullptr;
    std::vector<Held>  held_;
};

}  // namespace tc8::sce
