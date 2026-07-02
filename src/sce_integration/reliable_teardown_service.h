#pragma once

#include <cstdint>
#include <memory>
#include <utility>

#include "sce_integration/captured_frame_observer.h"
#include "someip/protocol.h"  // MessageType::NOTIFICATION.
#include "stimulus/subscribe_tcp_session.h"
#include "tc8/captured_event.h"

namespace tc8::sce {

// Drives the teardown of a reliable-subscribe session from the wire, for a
// reliable-event teardown silence shape: observe the reliable event delivered live
// over TCP, and once it is flowing (after `trigger_after` notifications) tear the
// connection down so the DUT deletes the subscription. The case then verifies "no
// further event after the teardown".
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
                                int trigger_after, ::tc8::stimulus::TcpTeardownMode mode)
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
            session_->applyTeardown(mode_);
        }
    }

    int observedCount() const { return observed_; }
    bool tornDown() const { return torn_down_; }

  private:
    std::unique_ptr<::tc8::stimulus::SubscribeEventgroupTcpSession> session_;
    std::uint16_t service_id_;
    std::uint16_t event_id_;
    int trigger_after_;
    ::tc8::stimulus::TcpTeardownMode mode_;
    int observed_ = 0;
    bool torn_down_ = false;
};

}  // namespace tc8::sce
