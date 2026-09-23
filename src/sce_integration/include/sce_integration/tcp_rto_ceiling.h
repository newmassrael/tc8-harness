#pragma once

#include <chrono>
#include <cstdint>
#include <thread>

#include "sce_integration/dut_control.h"
#include "sce_integration/tcp_captured.h"

namespace tc8::sce::tcp {

// TCP_RETRANSMISSION_TO_08/_09 grade an RTO upper bound of 2*MSL, MSL = 30 s,
// within 5 %. Their SCXML guards read these, so the grading band
// and the bound the observation stops at are one value.
inline constexpr std::uint32_t kTwoMslRtoLowerUs = 57'000'000U;
inline constexpr std::uint32_t kTwoMslRtoUpperUs = 63'000'000U;

struct RtoCeilingObservation {
    ::tc8::RtoCeilingOutcome outcome = ::tc8::RtoCeilingOutcome::NotObserved;
    bool       valid = false;  // at least one probe answered; `last` is real
    DutTcpInfo last{};
};

// Watches a retransmitting DUT socket until its RTO stops growing.
//
// RFC 6298 §5.5 doubles the RTO on every retransmission timeout, and only the
// upper bound may stop the doubling. So the bound is seen DIRECTLY, at the
// first timeout whose new RTO is less than twice the one before it. Two rules
// keep that reading honest:
//
//   * The comparison is across timeouts (tcpi_retransmits advancing), never
//     across polls. An RTO that reads the same on two polls with no timeout
//     in between is a timer still running, not a plateau.
//   * An RTO that has not grown yet is not read as capped. A stack may hold
//     its first timeouts flat before it backs off (Linux's linear SYN
//     timeouts); that is a backoff question, graded by _05, not a ceiling.
//
// Stops early once the RTO passes `upper_us`, because the bound is already
// exceeded, and when a probe that has answered stops answering, because the
// DUT has dropped the connection and there is no RTO left to watch.
inline RtoCeilingObservation observeRtoCeiling(IDutControl& dut,
                                               DutSocket sock,
                                               std::chrono::milliseconds budget,
                                               std::chrono::milliseconds poll,
                                               std::uint32_t upper_us) {
    // The RTO is exact integer doubling; the margin only absorbs the stack's
    // timer granularity. A 60 s cap reached from 32 s reads 60/64 = 94 %.
    constexpr std::uint64_t kDoublingMarginPct = 97U;
    constexpr std::uint8_t  kMaxShift          = 30U;

    RtoCeilingObservation obs;
    bool grown = false;
    const auto start = std::chrono::steady_clock::now();
    while (std::chrono::steady_clock::now() - start < budget) {
        std::this_thread::sleep_for(poll);
        const auto probe = dut.tcpStateProbe()->queryInfo(sock);
        if (!probe) {
            if (obs.valid) {
                obs.outcome = ::tc8::RtoCeilingOutcome::SocketLost;
                return obs;
            }
            continue;
        }
        const DutTcpInfo prev = obs.last;
        const bool had_prev = obs.valid;
        obs.last  = *probe;
        obs.valid = true;

        if (obs.last.rto_us > upper_us) {
            obs.outcome = ::tc8::RtoCeilingOutcome::UpperBoundExceeded;
            return obs;
        }
        if (!had_prev || prev.rto_us == 0U ||
            obs.last.retransmits <= prev.retransmits) {
            continue;
        }
        const auto timeouts = static_cast<std::uint8_t>(obs.last.retransmits - prev.retransmits);
        const std::uint64_t doubled =
            static_cast<std::uint64_t>(prev.rto_us) << (timeouts < kMaxShift ? timeouts : kMaxShift);
        if (grown && static_cast<std::uint64_t>(obs.last.rto_us) * 100U < doubled * kDoublingMarginPct) {
            obs.outcome = ::tc8::RtoCeilingOutcome::CeilingReached;
            return obs;
        }
        if (obs.last.rto_us > prev.rto_us) grown = true;
    }
    if (obs.valid) obs.outcome = ::tc8::RtoCeilingOutcome::BudgetExhausted;
    return obs;
}

}  // namespace tc8::sce::tcp
