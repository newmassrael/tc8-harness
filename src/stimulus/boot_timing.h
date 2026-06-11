#pragma once

#include <chrono>

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

}  // namespace tc8::stimulus
