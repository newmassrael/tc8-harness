#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string>

#include "tc8/test_defaults.h"

#include "sce_integration/captured_trace.h"
#include "sce_integration/tcp_captured.h"

// Captured contexts that belong to ONE TCP case each (or to the cases sharing one
// mechanism), as someip_case_captured.h does for SOME/IP: a slot a case writes
// from its stimulus or dispatch and reads in its SCXML lives in its own type, which IS-A TcpCaptured so the shared
// dispatch fills it and every shared guard still reads. Nothing here is written
// by fillTcpCapturedFromFrame, so each slot keeps its value across frames.

namespace tc8 {

// TCP_PROBING_WINDOWS_05: did the first zero-window probe wait out the DUT's
// retransmission timeout? Pcap-domain microseconds (`observed_ts_us`):
//   - dut_rto_us: the DUT's retransmission timeout on this connection, measured
//     by the stimulus as the gap between its first data segment and that
//     segment's retransmission. 0 until measured.
//   - zero_window_since_ts_us: when the tester's zero-window ACK was captured,
//     the instant the zero window began. 0 until the ACK is seen.
struct TcpProbingWindows05Captured : TcpCaptured {
    std::int64_t dut_rto_us = 0;
    std::int64_t zero_window_since_ts_us = 0;

    // The frame being dispatched came at least one retransmission timeout after
    // the zero window began, less TC8's millisecond tolerance
    // (<MillisecToleranceTime>, tc8::defaults). Neither this nor its converse
    // holds until both slots are set.
    bool waited_out_rto() const noexcept {
        return measured() && sinceZeroWindowUs() + toleranceUs() >= dut_rto_us;
    }
    bool came_before_rto() const noexcept {
        return measured() && sinceZeroWindowUs() + toleranceUs() < dut_rto_us;
    }

private:
    bool measured() const noexcept {
        return dut_rto_us > 0 && zero_window_since_ts_us > 0;
    }
    std::int64_t sinceZeroWindowUs() const noexcept {
        return observed_ts_us - zero_window_since_ts_us;
    }
    static constexpr std::int64_t toleranceUs() noexcept {
        return std::chrono::duration_cast<std::chrono::microseconds>(
                   ::tc8::defaults::kMillisecToleranceTime)
            .count();
    }
};

// TCP_PROBING_WINDOWS_06: does the interval between zero-window probes keep growing?
// RFC 1122 asks for an exponentially growing interval BETWEEN successive probes and
// names no base, so the case compares one inter-probe interval with the one before it
// instead of with a number tuned to one stack's timer. Three probes give two such
// intervals, probe 1 to probe 2 and probe 2 to probe 3; the wait before probe 1 is not
// one of them (and is not measurable from the wire alone: the persist timer starts
// when data is queued behind the closed window, which the tester does not see).
// Pcap-domain microseconds (`observed_ts_us`):
//   - fired_ts_us: the capture times of the frames that advanced the machine, in
//     order: the first data segment, probe 1, probe 2. Recorded as each transition
//     fires, so the guard on probe 3 finds the earlier probes' times here.
// The second interval has to exceed the first by a factor of 7/4: a doubling schedule
// clears it with room, a linear one has fallen to 3/2 by then and does not, and a
// constant one never does.
struct TcpProbingWindows06Captured : TcpCaptured {
    std::array<std::int64_t, 3> fired_ts_us{};
    std::uint8_t fired_count = 0;

    // Hides CapturedFrameTiming::snapshotFired, which the shared dispatch calls
    // through this type, to record the fired frame's time before the base advances.
    void snapshotFired() noexcept {
        if (fired_count < fired_ts_us.size()) {
            fired_ts_us[fired_count++] = observed_ts_us;
        }
        TcpCaptured::snapshotFired();
    }

    // Probe 3 is being dispatched: the data segment, probe 1 and probe 2 have fired.
    bool probe_interval_grew() const noexcept {
        return measured() && grew(observed_ts_us - fired_ts_us[2],
                                  fired_ts_us[2] - fired_ts_us[1]);
    }
    bool probe_interval_did_not_grow() const noexcept {
        return measured() && !grew(observed_ts_us - fired_ts_us[2],
                                   fired_ts_us[2] - fired_ts_us[1]);
    }

private:
    bool measured() const noexcept {
        return fired_count >= 3 && fired_ts_us[2] > fired_ts_us[1];
    }
    // `next` exceeds `previous` by more than 7/4, compared in integers.
    static constexpr bool grew(std::int64_t next, std::int64_t previous) noexcept {
        return next * 4 > previous * 7;
    }
};

// TCP_MSS_OPTIONS_01 / _05, the DUT liveness probe (dut_liveness.h):
//   - liveness_dut_ip: the DUT identity address (`TestConfig::dut.ip`, network
//     order) the probe went to, written by the stimulus, so the dispatch can tell
//     the DUT's Echo Reply from any other; 0 matches nothing.
//   - liveness_echo_seq: which probe the Echo Reply being dispatched answers,
//     written by the dispatch just before its `dut_echo_reply` event; 0 before any.
// One type for both cases because they share the probe, not a slot of either.
struct TcpLivenessCaptured : TcpCaptured {
    std::uint32_t liveness_dut_ip = 0;
    std::uint16_t liveness_echo_seq = 0;
};

inline void appendCapturedJson(std::string &out, const TcpLivenessCaptured &c) {
    out.append("{");
    appendTcpCapturedMembersJson(out, c);
    ::tc8::sce::appendUintJson(out, ",\"liveness_echo_seq\":", c.liveness_echo_seq);
    out.append("}");
}

inline void appendCapturedJson(std::string &out, const TcpProbingWindows06Captured &c) {
    out.append("{");
    appendTcpCapturedMembersJson(out, c);
    ::tc8::sce::appendI64Json(out, ",\"probe1_ts_us\":", c.fired_ts_us[1]);
    ::tc8::sce::appendI64Json(out, ",\"probe2_ts_us\":", c.fired_ts_us[2]);
    out.append("}");
}

inline void appendCapturedJson(std::string &out, const TcpProbingWindows05Captured &c) {
    out.append("{");
    appendTcpCapturedMembersJson(out, c);
    ::tc8::sce::appendI64Json(out, ",\"dut_rto_us\":", c.dut_rto_us);
    ::tc8::sce::appendI64Json(out, ",\"zero_window_since_ts_us\":", c.zero_window_since_ts_us);
    out.append("}");
}

}  // namespace tc8
