#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <string_view>
#include <thread>

#include "sce_integration/dut_socket_control.h"
#include "sce_integration/stimulus_context.h"
#include "sce_integration/stimulus_observation.h"
#include "sce_integration/tcp_case_captured.h"
#include "sce_integration/tcp_observation.h"
#include "sce_integration/tcp_retransmission_timing.h"

namespace tc8::sce::tcp {

// One DUT segment and its retransmissions, watched the way every retransmission-timer
// case watches them: on the case's own capture, each retransmission waited for as long
// as the DUT's own RTO says it will take (tcp_retransmission_timing.h), and the DUT's
// TCP_INFO read right after each one is seen. What it found is written into a
// TcpRetransmissionSeriesCaptured, whose predicates the case's SCXML grades.
//
// Shared because the cases that watch a series differ only in which segment they watch
// (a data segment, a SYN) and how the DUT is brought to send it; the waiting, the reading
// and the telling of a capture miss from a DUT that stopped are one mechanism, written
// once.

// The case's predicate for the watched segment captured after `after_ts_us`; the same
// predicate with the previous copy's capture time matches its next retransmission.
using SegmentAfter = std::function<ObservationPredicate(std::int64_t after_ts_us)>;

// The names the waits are recorded under when they are not met.
using RetransmissionWaitNames = std::array<std::string_view, 3>;

// The DUT's TCP_INFO once it counts at least `k` retransmissions. A retransmission the
// wire showed is counted by the DUT a moment after it is sent (Linux sends it, then
// doubles the RTO and counts it), so the counter is polled briefly until it agrees.
// Empty when it does not within the bound, or cannot be read.
inline std::optional<DutTcpInfo> tcpInfoOnceCounted(StimulusContext &ctx, DutSocket sock, std::uint8_t k) {
    constexpr std::chrono::milliseconds kPoll{20};
    constexpr std::chrono::milliseconds kBound{1000};
    const auto until = std::chrono::steady_clock::now() + kBound;
    while (true) {
        const auto info = ctx.dut.tcpInfoProbe()->queryInfo(sock);
        if (info && info->retransmits >= k) {
            return info;
        }
        if (std::chrono::steady_clock::now() >= until) {
            return std::nullopt;
        }
        std::this_thread::sleep_for(kPoll);
    }
}

// The DUT's TCP_INFO after the k-th retransmission, into the `ut_tcpi_p<k>_*` slots.
inline void storeSnapshot(TcpRetransmissionSeriesCaptured &c, std::uint8_t k,
                          const std::optional<DutTcpInfo> &s) {
    const DutTcpInfo v = s.value_or(DutTcpInfo{});
    switch (k) {
        case 1:
            c.ut_tcpi_p1_valid = s.has_value();
            c.ut_tcpi_p1_state = v.state;
            c.ut_tcpi_p1_rto_us = v.rto_us;
            c.ut_tcpi_p1_retransmits = v.retransmits;
            c.ut_tcpi_p1_unacked = v.unacked;
            break;
        case 2:
            c.ut_tcpi_p2_valid = s.has_value();
            c.ut_tcpi_p2_state = v.state;
            c.ut_tcpi_p2_rto_us = v.rto_us;
            c.ut_tcpi_p2_retransmits = v.retransmits;
            c.ut_tcpi_p2_unacked = v.unacked;
            break;
        default:
            c.ut_tcpi_p3_valid = s.has_value();
            c.ut_tcpi_p3_state = v.state;
            c.ut_tcpi_p3_rto_us = v.rto_us;
            c.ut_tcpi_p3_retransmits = v.retransmits;
            c.ut_tcpi_p3_unacked = v.unacked;
            break;
    }
}

// Watch up to `count` (at most 3) retransmissions of the segment first captured at
// `first_ts_us`, from the cursor `from` taken before the segment was provoked. Fills
// `c.segment_ts_us`, `c.retransmissions_seen`, `c.ut_tcpi_p<k>_*` and, when a window
// elapses unseen, `c.missed_*`. The first wait uses the DUT's RTO read once the segment
// is out.
inline void watchRetransmissions(TcpRetransmissionSeriesCaptured &c, StimulusContext &ctx,
                                 DutSocket sock, ObservationCursor from,
                                 const SegmentAfter &segment_after, std::int64_t first_ts_us,
                                 std::uint8_t count, const RetransmissionWaitNames &names) {
    using std::chrono::microseconds;
    c.segment_ts_us[0] = first_ts_us;
    const auto initial = ctx.dut.tcpInfoProbe()->queryInfo(sock);
    microseconds rto{initial ? initial->rto_us : 0U};
    c.initial_rto_us = initial ? initial->rto_us : 0U;
    c.initial_rto_valid = initial.has_value();
    microseconds last_interval{0};
    for (std::uint8_t k = 1; k <= count && k <= 3; ++k) {
        const auto retransmission = ctx.observer.observeWithin(
            names[k - 1], from, segment_after(c.segment_ts_us[k - 1]),
            nextRetransmissionBound(rto, last_interval));
        if (!retransmission) {
            // The window elapsed with nothing on the wire. The DUT's counter tells a
            // retransmission the capture missed from one the DUT never sent.
            const auto now = ctx.dut.tcpInfoProbe()->queryInfo(sock);
            c.missed_query_valid = now.has_value();
            c.missed_retransmits = now ? now->retransmits : std::uint8_t{0};
            return;
        }
        c.segment_ts_us[k] = segmentOf(retransmission->view()).observed_ts_us;
        c.retransmissions_seen = k;
        last_interval = microseconds(c.segment_ts_us[k] - c.segment_ts_us[k - 1]);
        const auto snapshot = tcpInfoOnceCounted(ctx, sock, k);
        storeSnapshot(c, k, snapshot);
        rto = microseconds(snapshot ? snapshot->rto_us : 0U);
    }
}

}  // namespace tc8::sce::tcp
