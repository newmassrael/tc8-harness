#pragma once

#include <atomic>
#include <cstdint>
#include <thread>

namespace tc8::dut {

// Raw-UDP SOME/IP-SD client-mode runner. Started by the
// `clientServiceActivate` Fire&Forget Method (TC8 §5.1.4.3.3) and stopped by
// `clientServiceDeactivate`. Emits `FindService` for SERVICE-ID-2 (0xF4E8) on
// the SD multicast group during the Start-Up Phase only — per
// PRS_SOMEIPSD_00350/00351 the Main Phase must carry no FindService — so
// after the repetition burst the thread idles until stopped.
//
// The runner stays out of the vsomeip lifecycle entirely: it opens its own
// SOCK_DGRAM socket bound to the SD port (30490), with `SO_REUSEADDR` so it
// coexists with vsomeip's existing bind. The DUT's 472 server-side cases are
// therefore unaffected — vsomeip continues to drive cyclic OfferService for
// SERVICE-ID-1 from the main thread.
//
// §5.1.6 SOMEIP_ETS_098/099/100 verdicts only depend on observing the DUT's
// FindService emit pattern, so a one-shot Repetition-Phase burst is the
// minimum infrastructure that satisfies the spec's "Start-Up only" assertion.
// _101 (StopOfferService → DUT stops) and _097 (TCP retry) build on this
// baseline; see project_someip_ets_seed_coverage.md for the forward outline.
class ClientModeRunner {
public:
    ClientModeRunner();
    ~ClientModeRunner();

    ClientModeRunner(const ClientModeRunner&) = delete;
    ClientModeRunner& operator=(const ClientModeRunner&) = delete;

    // Starts the FindService emitter thread after waiting `delay_ms`. Idempotent
    // when already running.
    void start(std::uint8_t delay_ms);

    // Signals stop and joins the thread. Safe to call when not running.
    void stop();

private:
    void run();

    // `true` when the thread is NOT running. Initial value `true` mirrors a
    // freshly-constructed runner — start() flips it to false to mark
    // "running" and stop() flips it back to true.
    std::atomic<bool> stop_flag_{true};
    std::thread emit_thread_;
};

}  // namespace tc8::dut
