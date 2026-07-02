#pragma once

#include <cstdint>
#include <memory>
#include <utility>

#include "sce_integration/captured_frame_observer.h"
#include "sce_integration/tcp_pilot_common.h"  // tcp::TesterInboundDropScope (INPUT DROP RAII).
#include "someip/protocol.h"                    // MessageType::NOTIFICATION.
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
    SubscribeTcpTeardownService(std::unique_ptr<::tc8::stimulus::SubscribeEventgroupTcpSession> session,
                                std::uint16_t service_id, std::uint16_t event_id,
                                int trigger_after, TcpTeardownMode mode)
        : session_(std::move(session)),
          service_id_(service_id),
          event_id_(event_id),
          trigger_after_(trigger_after < 1 ? 1 : trigger_after),
          mode_(mode) {}

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
                if (mode_ == TcpTeardownMode::kRefuseWithRst) {
                    session_->refuseWithRst();
                } else {
                    drop_scope_ = std::make_unique<tcp::TesterInboundDropScope>(
                        session_->dutReliable(), session_->testerEndpoint());
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
    // The DROP filter for kDropIncoming — held so it stays installed across the
    // observation window and is removed (RAII) when this driver is torn down.
    std::unique_ptr<tcp::TesterInboundDropScope> drop_scope_;
    int observed_ = 0;
    bool torn_down_ = false;
};

}  // namespace tc8::sce
