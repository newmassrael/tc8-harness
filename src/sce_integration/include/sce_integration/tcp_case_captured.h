#pragma once

#include <chrono>
#include <cstdint>
#include <string>

#include "tc8/test_defaults.h"

#include "sce_integration/captured_trace.h"
#include "sce_integration/tcp_captured.h"

// Captured contexts that belong to ONE TCP case each, as someip_case_captured.h
// does for SOME/IP: a slot a single case writes from its stimulus and reads in
// its SCXML lives in that case's own type, which IS-A TcpCaptured so the shared
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

inline void appendCapturedJson(std::string &out, const TcpProbingWindows05Captured &c) {
    out.append("{");
    appendTcpCapturedMembersJson(out, c);
    ::tc8::sce::appendI64Json(out, ",\"dut_rto_us\":", c.dut_rto_us);
    ::tc8::sce::appendI64Json(out, ",\"zero_window_since_ts_us\":", c.zero_window_since_ts_us);
    out.append("}");
}

}  // namespace tc8
