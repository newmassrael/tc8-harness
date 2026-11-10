#pragma once

#include <sys/timerfd.h>
#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <utility>

#include "sce_integration/stimulus_context.h"
#include "sce_integration/test_runner.h"  // IBackgroundServiceOwner
#include "stimulus/tx_observer.h"         // reportTesterAction, kActionLinkDown / kActionLinkUp
#include "tc8/net/link_control.h"         // setLinkState
#include "tc8/pollable_service.h"
#include "tc8/unperformed_stimulus.h"

namespace tc8::sce {

// The names an unperformed bounce is recorded under (UnperformedStimulus); they reach a
// report as `inconclusive:stimulus_<name>_not_performed`.
inline constexpr const char *kTesterLinkDownStimulus = "tester_link_down";
inline constexpr const char *kTesterLinkUpStimulus = "tester_link_up";

// Brings a link back up when its deadline passes, from the capture loop: the runner
// owns it as a background service, polls its timerfd with the capture and calls
// onReadable every pass, so the restore needs no thread of its own and nothing waits
// for it. Created disarmed; arm() starts the deadline once the link is actually down.
// An armed timer that is destroyed before its deadline (the run ended first) restores
// the link then, so a case cannot leave the tester's link down behind it.
class LinkRestoreTimer final : public ::tc8::IPollableService {
public:
    // `set_link(up)` changes the link and reports whether the kernel accepted it.
    explicit LinkRestoreTimer(std::function<bool(bool up)> set_link)
        : set_link_(std::move(set_link)),
          fd_(::timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC)) {}

    ~LinkRestoreTimer() override {
        if (armed_ && !restored_) {
            restore();
        }
        if (fd_ >= 0) {
            ::close(fd_);
        }
    }

    LinkRestoreTimer(const LinkRestoreTimer &) = delete;
    LinkRestoreTimer &operator=(const LinkRestoreTimer &) = delete;

    // False when the timer could not be created: then nothing can restore the link
    // on time, and the caller must not take it down.
    bool valid() const {
        return fd_ >= 0;
    }

    // Start the deadline `after` from now. False when the kernel refused it.
    bool arm(std::chrono::milliseconds after) {
        itimerspec spec{};
        const auto ms = after.count() > 0 ? after.count() : 1;  // 0 would disarm the timerfd
        spec.it_value.tv_sec = static_cast<time_t>(ms / 1000);
        spec.it_value.tv_nsec = static_cast<long>((ms % 1000) * 1000000);
        armed_ = ::timerfd_settime(fd_, 0, &spec, nullptr) == 0;
        return armed_;
    }

    bool restored() const {
        return restored_;
    }

    int pollFd() const override {
        return armed_ && !restored_ ? fd_ : -1;
    }

    void onReadable() override {
        if (!armed_ || restored_) {
            return;
        }
        std::uint64_t expirations = 0;
        if (::read(fd_, &expirations, sizeof(expirations)) == static_cast<ssize_t>(sizeof(expirations)) &&
            expirations != 0) {
            restore();
        }
    }

private:
    void restore() {
        restored_ = true;
        if (set_link_(true)) {
            ::tc8::stimulus::reportTesterAction(::tc8::stimulus::kActionLinkUp);
        } else {
            ::tc8::UnperformedStimulus::record(kTesterLinkUpStimulus);
        }
    }

    std::function<bool(bool up)> set_link_;
    int fd_;
    bool armed_ = false;
    bool restored_ = false;
};

// Take the tester's own link (`ctx.iface`) down now and bring it back up `outage`
// later, without blocking: the call returns at once, so the stimulus goes on and the
// capture loop keeps polling and grading through the outage and after it. On a veth
// pair the DUT's leg loses its carrier with it, so it is a genuine link loss for the
// DUT. While the link is down the capture sees nothing; the capture loop records the
// interval (CaptureStats::link_outages), and an absence graded over a window it falls
// in is unproven.
//
// Returns true when the link went down and its restore is armed. False when the bounce
// was not performed (no timer, or the kernel refused the change, e.g. without
// CAP_NET_ADMIN); the unperformed step is already recorded, so the run cannot be graded
// as though it had happened.
inline bool bounceTesterLink(StimulusContext &ctx, std::chrono::milliseconds outage) {
    const std::string iface(ctx.iface);
    auto restore = std::make_unique<LinkRestoreTimer>(
        [iface](bool up) { return ::tc8::net::setLinkState(iface, up); });
    if (!restore->valid()) {
        ::tc8::UnperformedStimulus::record(kTesterLinkDownStimulus);
        return false;
    }
    if (!::tc8::net::setLinkState(iface, /*up=*/false)) {
        ::tc8::UnperformedStimulus::record(kTesterLinkDownStimulus);
        return false;
    }
    ::tc8::stimulus::reportTesterAction(::tc8::stimulus::kActionLinkDown);
    if (!restore->arm(outage)) {
        // No deadline: bring the link back now rather than leave it down for the run.
        ::tc8::net::setLinkState(iface, /*up=*/true);
        ::tc8::UnperformedStimulus::record(kTesterLinkUpStimulus);
        return false;
    }
    ctx.services.adoptService(std::move(restore));
    return true;
}

}  // namespace tc8::sce
