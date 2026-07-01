#pragma once

#include <cstdint>

namespace tc8::dut {

// Edge-detector for the warm-suspendInterface resume counter. The detached suspend
// thread bumps a monotonic counter on each successful re-offer
// (ServerRole::resumeCount()); the DUT main loop feeds that counter here every pass
// and fires IEtsExtension::onReactivate whenever advanced() reports the counter moved.
//
// LEVEL-triggered, not one-fire-per-increment: if the counter advances by more than
// one between two polls (multiple re-offers inside one loop window), advanced()
// reports true ONCE, not once per increment. That matches the hook's idempotent
// "re-apply / re-anchor" contract — re-anchoring to the latest activation once is
// sufficient — but it is not one-delivery-per-re-offer. Seed the cursor with the
// counter's value at loop entry so the initial activation is not mistaken for a
// re-activation.
//
// Extracted from dut_main's loop so this fallible marshalling step (seed / no-fire-
// when-equal / fire-once-on-advance / coalesce-a-burst / wrap-safe) is unit-testable
// without a running DUT — see unit_tests/resume_edge_test.cpp.
class ResumeEdge {
public:
    explicit ResumeEdge(std::uint32_t seed) : last_(seed) {}

    // True exactly when `current` differs from the last value advanced() accepted,
    // moving the cursor to `current`. Compares with != (not >) so a 2^32 wrap of the
    // monotonic counter still fires instead of silently stalling.
    bool advanced(std::uint32_t current) {
        if (current == last_) {
            return false;
        }
        last_ = current;
        return true;
    }

private:
    std::uint32_t last_;
};

}  // namespace tc8::dut
