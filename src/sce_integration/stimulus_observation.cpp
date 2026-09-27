#include "sce_integration/stimulus_observation.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <utility>

#include "tc8/unperformed_stimulus.h"

namespace tc8::sce {

namespace {

// The longest a wait blocks before re-draining. The capture loop's own idle
// quantum, so an awaited frame is seen as promptly as the loop would see it; a
// frame arriving mid-wait wakes it at once anyway (ICapturePump::waitForInput).
constexpr std::chrono::milliseconds kWaitQuantum{20};

long long msBetween(std::chrono::steady_clock::time_point a,
                    std::chrono::steady_clock::time_point b) {
    return static_cast<long long>(
        std::chrono::duration_cast<std::chrono::milliseconds>(b - a).count());
}

}  // namespace

StimulusObservation::StimulusObservation(Clock clock) : clock_(std::move(clock)) {}

void StimulusObservation::hold(const ::tc8::CapturedEvent &ev, int pcap_frame_idx) {
    held_.push_back(Held{OwnedCapturedEvent{ev}, pcap_frame_idx});
}

void StimulusObservation::holdMarker(std::string_view name, int pcap_frame_idx) {
    held_.push_back(Held{Marker{std::string(name)}, pcap_frame_idx});
}

void StimulusObservation::release(const std::function<void(const Held &)> &sink) {
    for (const Held &h : held_) {
        sink(h);
    }
    held_.clear();
}

void StimulusObservation::requirePump(std::string_view name) const {
    if (pump_ != nullptr) {
        return;
    }
    // A programming error in a case, not a run condition: the listen window is
    // open, the state machine is consuming frames, and the one thing this facility
    // guarantees — that a frame drained for a wait is still delivered to the state
    // machine in order — can no longer hold. Refused loudly rather than degraded
    // into a wait that silently reorders the capture.
    std::fprintf(stderr,
                 "fatal: stimulus observation '%.*s' requested outside the stimulus. "
                 "An observation can be awaited only while the stimulus runs, before the "
                 "listen window opens.\n",
                 static_cast<int>(name.size()), name.data());
    std::abort();
}

ObservationCursor StimulusObservation::mark() {
    requirePump("mark");
    // Drain first so everything already on the wire falls before the cursor. A
    // failed drain still yields a cursor; the await from it meets the same
    // failure and reports it under its own name.
    (void)pump_->drain();
    return ObservationCursor{held_.size()};
}

const ::tc8::CapturedEvent *StimulusObservation::scan(std::size_t &position,
                                                      const ObservationPredicate &predicate) const {
    for (; position < held_.size(); ++position) {
        const auto *ev = std::get_if<OwnedCapturedEvent>(&held_[position].item);
        if (ev != nullptr && predicate(ev->view())) {
            return &ev->view();
        }
    }
    return nullptr;
}

std::optional<OwnedCapturedEvent> StimulusObservation::awaitObservation(
    std::string_view name, ObservationCursor from, const ObservationPredicate &predicate,
    std::chrono::milliseconds bound) {
    requirePump(name);
    const auto started = clock_();
    const auto deadline = started + bound;
    std::size_t position = std::min(from.position, held_.size());

    const auto not_seen = [&](const char *why) -> std::optional<OwnedCapturedEvent> {
        std::printf("stimulus : awaited '%.*s' NOT observed (%s, %lld ms)\n",
                    static_cast<int>(name.size()), name.data(), why, msBetween(started, clock_()));
        ::tc8::UnperformedStimulus::record(std::string(name));
        return std::nullopt;
    };

    for (;;) {
        // Drain before every check, including the first, so a zero bound still
        // considers what has already arrived.
        const ICapturePump::Drained drained = pump_->drain();
        if (const ::tc8::CapturedEvent *ev = scan(position, predicate)) {
            // `scan` stopped ON the match, so `position` is its index.
            std::printf("stimulus : awaited '%.*s' observed after %lld ms (pcap frame %d)\n",
                        static_cast<int>(name.size()), name.data(),
                        msBetween(started, clock_()), held_[position].pcap_frame_idx);
            return OwnedCapturedEvent{*ev};
        }
        switch (drained.status) {
            case ICapturePump::Status::kOk:
                break;
            case ICapturePump::Status::kEndOfCapture:
                return not_seen("capture ended");
            case ICapturePump::Status::kError:
                return not_seen("capture failed");
            case ICapturePump::Status::kStopped:
                // The run was interrupted; its verdict is `error:interrupted`,
                // which outranks a precondition note, so nothing is recorded.
                return std::nullopt;
        }
        const auto now = clock_();
        if (now >= deadline) {
            return not_seen("bound elapsed");
        }
        pump_->waitForInput(std::min(
            kWaitQuantum,
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now)));
    }
}

}  // namespace tc8::sce
