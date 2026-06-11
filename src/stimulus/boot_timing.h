#pragma once

#include <chrono>
#include <thread>

namespace tc8::stimulus {

// Timing envelope for tester-side boot-window stimulus sequences —
// stimuli that must ride out the DUT's bring-up before the first emit
// lands (SOME/IP-SD FindService/Subscribe, UT OpTriggerSendUdp, ...):
//   - `initial_wait` before the first emit, so the DUT's service init
//     (vsomeip initial_delay_min/max + bootstrap, UT server bind) can
//     complete.
//   - `retry_interval` between consecutive emits.
//   - `total_emits` total stimulus datagrams sent.
// Total blocking time = initial_wait + (total_emits - 1) * retry_interval.
//
// `TestConfig::stimulus_timing` carries one of these per run; the CLI
// overrides the defaults via `--stimulus-wait`, `--stimulus-retry`,
// `--stimulus-emits` for DUTs with slower/faster bring-up.
struct BootTiming {
    std::chrono::milliseconds initial_wait{1500};
    std::chrono::milliseconds retry_interval{1000};
    int total_emits{2};
};

// Drives one boot-cadence sequence: block for `initial_wait`, then call
// `emit_once(i)` for i in [0, total_emits) with `retry_interval` between
// calls. Stops at the first non-zero return and forwards it; returns 0
// when every emit succeeded (no retry-on-failure — the cadence is fixed
// so higher layers can reason about total wall time). Single source of
// the loop shared by the SD boot emitters (`emitFindServiceBoot`,
// `emitSubscribeEventgroupBoot*`) and the UT boot emitter
// (`emitTriggerSendUdpBoot`).
template <typename EmitOnce>
int runBootCadence(const BootTiming &timing, EmitOnce &&emit_once) {
    std::this_thread::sleep_for(timing.initial_wait);
    for (int i = 0; i < timing.total_emits; ++i) {
        if (i > 0) {
            std::this_thread::sleep_for(timing.retry_interval);
        }
        const int rc = emit_once(i);
        if (rc != 0) {
            return rc;
        }
    }
    return 0;
}

}  // namespace tc8::stimulus
