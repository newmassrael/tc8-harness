#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <utility>

#include "sce_integration/captured_frame_observer.h"
#include "sce_integration/tcp_pilot_common.h"  // tcp::TesterInboundDropScope (INPUT DROP RAII).
#include "tc8/someip/protocol.h"                    // MessageType::NOTIFICATION.
#include "stimulus/subscribe_tcp_session.h"
#include "tc8/captured_event.h"

namespace tc8::sce {

// How a reliable-subscribe connection is torn down so the DUT deletes the
// subscription. kDropIncoming is the silent "connection lost" (half-open) shape via
// an sce-layer INPUT DROP on the connection's 4-tuple (tcp::TesterInboundDropScope);
// kRefuseWithRst is the "connection refused" shape via the session's own abortive
// close (RST). The mechanisms live in their correct layers — packet filter in sce,
// socket close in the transport session — and this driver dispatches between them.
enum class TcpTeardownMode { kDropIncoming, kRefuseWithRst };

// Installs the inbound DROP for a connection and returns what keeps it installed: the
// filter is removed when the last copy of the returned owner is released. An empty owner
// means nothing was installed (nothing to resume). Injected so the resume logic is
// testable without a packet filter; the default installs tcp::TesterInboundDropScope.
using InboundDropInstaller = std::function<std::shared_ptr<void>(
    const ::tc8::stimulus::Endpoint &dut, const ::tc8::stimulus::Endpoint &tester)>;

inline std::shared_ptr<void> installInboundDrop(const ::tc8::stimulus::Endpoint &dut,
                                                const ::tc8::stimulus::Endpoint &tester) {
    auto scope = std::make_shared<tcp::TesterInboundDropScope>(dut, tester);
    if (!scope->installed()) {
        return nullptr;
    }
    return scope;
}

// The installed drop of one teardown service, shared with the handles the case holds.
struct InboundDropState {
    std::mutex mutex;
    std::shared_ptr<void> drop;  // empty: not dropped, or already resumed
};

// A case's handle on a teardown service it handed to the runner. The runner owns the
// service, so the case cannot keep a pointer to it; it keeps this instead. A copy is
// cheap, and it stays safe after the service is gone (resume() then returns false).
class TcpResume {
  public:
    TcpResume() = default;
    explicit TcpResume(std::weak_ptr<InboundDropState> state) : state_(std::move(state)) {}

    // The tester goes back to answering the connection's segments: releases the inbound
    // drop and reports the "resume" action under `step`. Returns true when it released a
    // drop, and false (reporting nothing) when there was none to release: the service is
    // not in drop mode, has not dropped yet, was already resumed, or is gone. Callable
    // from any thread, so a scheduled step on the capture thread may call it.
    bool resume(int step) const {
        const auto state = state_.lock();
        if (!state) {
            return false;
        }
        std::shared_ptr<void> released;
        {
            std::lock_guard<std::mutex> lock(state->mutex);
            released = std::move(state->drop);
        }
        if (!released) {
            return false;
        }
        released.reset();  // removes the filter before the step is reported
        const ::tc8::stimulus::TxSpecStep scope(step);
        ::tc8::stimulus::reportTesterAction(::tc8::stimulus::kActionResume);
        return true;
    }

  private:
    std::weak_ptr<InboundDropState> state_;
};

// Drives the teardown of a reliable-subscribe session from the wire, for a
// reliable-event teardown silence shape: observe the reliable event delivered live
// over TCP, and once it is flowing (after `trigger_after` notifications) tear the
// connection down so the DUT is expected to delete the subscription. A consuming
// case then verifies "no further event after the teardown".
//
// OEM-enabling seam: no in-tree case wires this driver yet (the reliable-teardown
// cases are out-of-tree). In-tree coverage (reliable_teardown_service_test) is the
// observe-count-and-fire logic ONLY; the DUT-side deletion is unexercised here.
//
// This lives in the sce layer (not on the stimulus-layer session) because gating
// on an OBSERVED frame needs ::tc8::CapturedEvent, which the pollable/stimulus
// layer deliberately does not depend on. It OWNS the session so a single object
// adopted via IBackgroundServiceOwner::adoptObservingService plays both roles:
// its fd is drained by the capture loop (delegated to the session) and it reacts
// to observed frames to fire the teardown — no wall-clock coupling.
class SubscribeTcpTeardownService : public IFrameObservingService {
  public:
    // `session` must already have been subscribed. `service_id`/`event_id` identify
    // the reliable NOTIFICATION to count (e.g. 0xF4E7 / 0x8003). After
    // `trigger_after` such notifications arrive over TCP, `mode`'s teardown fires
    // exactly once.
    //
    // `teardown_step` is the specification step the teardown performs (what its reports,
    // "tcp_reset" or "ignore_segments", are tagged with), or kNoSpecStep. It is given
    // here rather than by a TxSpecStep because the teardown fires on the capture
    // thread, which a scope on the case's thread does not reach.
    SubscribeTcpTeardownService(std::unique_ptr<::tc8::stimulus::SubscribeEventgroupTcpSession> session,
                                std::uint16_t service_id, std::uint16_t event_id,
                                int trigger_after, TcpTeardownMode mode,
                                int teardown_step = ::tc8::stimulus::kNoSpecStep,
                                InboundDropInstaller install_drop = installInboundDrop)
        : session_(std::move(session)),
          service_id_(service_id),
          event_id_(event_id),
          trigger_after_(trigger_after < 1 ? 1 : trigger_after),
          mode_(mode),
          teardown_step_(teardown_step),
          install_drop_(std::move(install_drop)) {}

    // The handle a case keeps to end the drop before the case does (see TcpResume). Take
    // it before handing the service to the runner.
    TcpResume resumer() const { return TcpResume(drop_state_); }

    // TcpResume::resume on this service, for a holder of the service itself.
    bool resume(int step) const { return resumer().resume(step); }

    // IPollableService — delegate the held reliable connection to the capture loop.
    int pollFd() const override { return session_ ? session_->pollFd() : -1; }
    void onReadable() override {
        if (session_) {
            session_->onReadable();
        }
    }

    // ICapturedFrameObserver — count the reliable event over TCP and, once it is
    // flowing, tear the connection down once.
    void onCapturedFrame(const ::tc8::CapturedEvent &ev) override {
        if (torn_down_ || !session_) {
            return;
        }
        const auto *f = std::get_if<::tc8::SomeIpFrame>(&ev);
        if (f == nullptr || !f->is_tcp) {
            return;
        }
        if (f->service_id != service_id_ || f->method_id != event_id_ ||
            f->message_type != static_cast<std::uint8_t>(::tc8::someip::MessageType::NOTIFICATION)) {
            return;
        }
        if (++observed_ >= trigger_after_) {
            torn_down_ = true;
            // An invalid (fd-less) session is inert — the counter still fires so the
            // logic is unit-testable, but no packet-filter/socket op runs.
            if (session_->valid()) {
                // Whatever the teardown reports is the step's, for as long as it runs.
                const ::tc8::stimulus::TxSpecStep step(teardown_step_);
                if (mode_ == TcpTeardownMode::kRefuseWithRst) {
                    session_->refuseWithRst();
                } else {
                    auto drop = install_drop_(session_->dutReliable(),
                                              session_->testerEndpoint());
                    std::lock_guard<std::mutex> lock(drop_state_->mutex);
                    drop_state_->drop = std::move(drop);
                }
            }
        }
    }

    int observedCount() const { return observed_; }
    bool tornDown() const { return torn_down_; }

  private:
    std::unique_ptr<::tc8::stimulus::SubscribeEventgroupTcpSession> session_;
    std::uint16_t service_id_;
    std::uint16_t event_id_;
    int trigger_after_;
    TcpTeardownMode mode_;
    int teardown_step_;
    InboundDropInstaller install_drop_;
    // The DROP filter for kDropIncoming — held so it stays installed across the
    // observation window and is removed (RAII) when this driver is torn down, or sooner
    // by TcpResume. Shared so a case's handle can reach it after the runner owns this.
    std::shared_ptr<InboundDropState> drop_state_ = std::make_shared<InboundDropState>();
    int observed_ = 0;
    bool torn_down_ = false;
};

}  // namespace tc8::sce
