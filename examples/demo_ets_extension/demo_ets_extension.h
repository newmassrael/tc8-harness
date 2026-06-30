#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <vector>

#include "ets_client_control.h"   // IEtsClientControl
#include "ets_control_channel.h"  // IEtsControlChannel
#include "ets_event_sink.h"       // IEtsEventSink
#include "ets_extension.h"        // IEtsExtension

namespace tc8::dut {

// Synthetic, NON-NDA demonstration of the IEtsExtension seam — a copy-paste
// starter an OEM adapts to offer its OWN (NDA) surface on the shared vsomeip
// application, selected at configure time via TC8_ETS_EXTENSION_SRC (see
// demo_ets_extension.cpp). It exercises all three seams: the SERVER-role
// IEtsEventSink (offerEvent + onMethod + the reply-capable onRequest), the
// CLIENT-role IEtsClientControl (subscribe/stop, a subscription-status edge that
// bounds the subscription lifetime by duration, plus an RPC call whose Response it
// captures), and the inbound IEtsControlChannel (offers a control service so a
// client-only DUT can be driven) — the client-role (CLT) topology shape: the
// tester drives a method, the DUT subscribes (for a bounded lifetime) or calls
// back, and a readback method replies with what it observed.
//
// The IDs are deliberately synthetic — outside the public ETS event range
// (0x80xx), its eventgroups (0x0002/0x0005/0x0007), and the trigger-method range
// (0x03..0x3A) — so this never collides with a real service and is safe in-tree.
// Two eventgroups are shown because real OEM events typically offer on two; the
// facade accepts one or more, so the count carries no requirement.
inline constexpr std::uint16_t kDemoEventId        = 0x7F01;
inline constexpr std::uint16_t kDemoEventgroupA    = 0x00F0;
inline constexpr std::uint16_t kDemoEventgroupB    = 0x00F5;
inline constexpr std::uint16_t kDemoTriggerMethod  = 0x07F0;

// CLIENT-role demo: a synthetic tester-offered service the demo DUT subscribes to
// (kDemoSubscribeMethod) and RPC-calls (kDemoCallMethod), and the local control
// methods that drive/read it back (kDemoReadbackMethod replies with the last
// captured Response payload via the reply-capable onRequest).
inline constexpr std::uint16_t kDemoTargetService    = 0x7F02;
inline constexpr std::uint16_t kDemoTargetInstance   = 0x0001;
inline constexpr std::uint16_t kDemoTargetEventgroup = 0x00F7;
inline constexpr std::uint16_t kDemoTargetEvent      = 0x7F80;
inline constexpr std::uint16_t kDemoTargetMethod     = 0x7F81;
inline constexpr std::uint16_t kDemoSubscribeMethod  = 0x07F1;
inline constexpr std::uint16_t kDemoCallMethod       = 0x07F2;
inline constexpr std::uint16_t kDemoReadbackMethod   = 0x07F3;
inline constexpr std::uint8_t  kDemoTargetMajor      = 0x01;

// CLIENT-role DURATION demo: once the subscription is ESTABLISHED (the target
// returns a SubscribeEventgroupAck), the demo holds it for this many DUT
// main-loop ticks, then stops it — the "subscribe for a bounded lifetime" shape
// a duration-bounded client case needs. Synthetic tick count, no wire/spec
// meaning; it just shows the timer being anchored to establishment, not startup.
inline constexpr int kDemoSubscriptionTicks = 3;

// CLIENT-ONLY delivery demo: a distinct CONTROL service the demo offers so a
// client-only DUT (which offers no event surface, so the server-sink onMethod
// never fires) can still be driven to subscribe. Synthetic ids; the control
// service is deliberately NOT kDemoTargetService — offering the subscribe target
// would let vsomeip satisfy the subscribe locally and emit no wire
// SubscribeEventgroup.
inline constexpr std::uint16_t kDemoControlService         = 0x7F03;
inline constexpr std::uint16_t kDemoControlInstance        = 0x0001;
inline constexpr std::uint16_t kDemoControlSubscribeMethod = 0x07F4;

// Header-only so the hermetic test can instantiate it directly (no link step)
// and the OEM can subclass/adapt it inline.
class DemoEtsExtension : public IEtsExtension {
public:
    void onRegister(EtsExtensionContext& ctx) override {
        IEtsEventSink& sink = ctx.sink;
        // Offer the demo event, then arm a trigger method that notifies it with
        // the request payload — the realistic "DUT emits event X when method Y
        // is called" shape. The handler captures `&sink` and runs on a vsomeip
        // thread; this is safe because dut_main owns the sink for the whole run
        // AND the concrete sink unregisters its handlers on destruction (see
        // ets_event_sink.cpp), so the captured reference cannot outlive the
        // registration.
        sink.offerEvent(kDemoEventId, {kDemoEventgroupA, kDemoEventgroupB});
        sink.onMethod(kDemoTriggerMethod,
                      [&sink](const std::vector<std::uint8_t>& payload) {
                          sink.notify(kDemoEventId, payload);
                      });

        // CLIENT demo: the DUT subscribes (UDP) to the synthetic target eventgroup
        // when driven — by kDemoSubscribeMethod on the offered ETS service (server
        // role) OR by the control trigger (client-only role). `driveSubscribe` is
        // the SINGLE definition of that action so the two delivery paths cannot
        // drift. It captures the client POINTER (owned by dut_main for the whole
        // run) instead of `this`, so the vsomeip-thread handlers hold no reference
        // to this extension — the same lifetime discipline as `&sink`.
        IEtsClientControl* client = &ctx.client;
        auto driveSubscribe = [client] {
            client->subscribeEventgroup(kDemoTargetService, kDemoTargetInstance,
                                        kDemoTargetEventgroup, {kDemoTargetEvent},
                                        /*reliable=*/false, kDemoTargetMajor);
        };
        sink.onMethod(kDemoSubscribeMethod,
                      [driveSubscribe](const std::vector<std::uint8_t>&) { driveSubscribe(); });

        // CLIENT-ONLY DELIVERY demo: in the client-role topology the DUT offers no
        // event surface, so the server-sink onMethod above never receives a
        // trigger. Offer a small CONTROL service (a distinct id, NOT the subscribe
        // target) on the inbound control channel and drive the SAME subscribe on it
        // — the delivery path a client-only DUT is driven through.
        ctx.control.offerControlMethod(
            kDemoControlService, kDemoControlInstance, kDemoControlSubscribeMethod,
            kDemoTargetMajor,
            [driveSubscribe](const std::vector<std::uint8_t>&) { driveSubscribe(); });

        // CLIENT DURATION demo: anchor a bounded subscription lifetime to the
        // instant the subscription is ESTABLISHED (the target's
        // SubscribeEventgroupAck), not to startup — which would race the tester's
        // OfferService. The status handler runs on a vsomeip thread, so it only
        // arms shared state (a captured shared_ptr, never `this`); onTick (DUT main
        // thread) counts the ticks down and issues the stop. Registered before any
        // subscribeEventgroup() so the Ack cannot precede the handler.
        auto lifetime = lifetime_;
        client->onSubscriptionStatus(kDemoTargetService, kDemoTargetInstance,
                                     kDemoTargetEventgroup,
                                     [lifetime](bool established) {
                                         if (!established) return;
                                         std::lock_guard<std::mutex> lock(lifetime->mutex);
                                         lifetime->armed = true;
                                         lifetime->ticks_remaining = kDemoSubscriptionTicks;
                                     });

        // RPC-CLIENT demo: capture the target method's Response into shared state,
        // call it on kDemoCallMethod, and reply with the captured payload on the
        // readback Request. The closures capture a COPY of the shared_ptr (not
        // `this`), so the response handler (a vsomeip thread) and the readback
        // reply (another) safely outlive this extension and serialise on the
        // state's mutex — the cross-thread pattern an OEM readback needs.
        auto last = last_response_;
        client->onResponse(kDemoTargetService, kDemoTargetInstance, kDemoTargetMethod,
                           [last](std::uint8_t rc,
                                  const std::vector<std::uint8_t>& payload) {
                               std::lock_guard<std::mutex> lock(last->mutex);
                               last->return_code = rc;
                               last->payload = payload;
                           });
        sink.onMethod(kDemoCallMethod,
                      [client](const std::vector<std::uint8_t>& payload) {
                          client->callMethod(kDemoTargetService, kDemoTargetInstance,
                                             kDemoTargetMethod, payload,
                                             /*reliable=*/false, kDemoTargetMajor);
                      });
        sink.onRequest(kDemoReadbackMethod,
                       [last](const std::vector<std::uint8_t>&) {
                           std::lock_guard<std::mutex> lock(last->mutex);
                           return last->payload;
                       });
    }

    // Count down the bounded subscription lifetime that the subscription-status
    // handler armed at establishment, and stop the subscription when it expires —
    // the duration-bounded client-subscribe shape. Runs on the DUT main thread
    // (it has ctx for the seam call); the vsomeip-thread status handler only armed
    // the shared counter. The seam call is made OUTSIDE the lock so a re-entrant
    // handler cannot deadlock.
    void onTick(EtsExtensionContext& ctx) override {
        bool expired = false;
        {
            std::lock_guard<std::mutex> lock(lifetime_->mutex);
            if (lifetime_->armed && lifetime_->ticks_remaining > 0 &&
                --lifetime_->ticks_remaining == 0) {
                lifetime_->armed = false;
                expired = true;
            }
        }
        if (expired) {
            ctx.client.stopSubscribeEventgroup(kDemoTargetService, kDemoTargetInstance,
                                               kDemoTargetEventgroup);
        }
    }

    // Stop the demo subscription on shutdown. Runs on the DUT main thread (not a
    // vsomeip handler). Safe even if the subscribe method was never Requested or
    // the duration already stopped it — stopSubscribeEventgroup is a no-op for an
    // unknown subscription.
    void onStop(EtsExtensionContext& ctx) override {
        ctx.client.stopSubscribeEventgroup(kDemoTargetService, kDemoTargetInstance,
                                           kDemoTargetEventgroup);
    }

private:
    // Last Response observed for the target method, shared with the vsomeip-thread
    // handlers via shared_ptr so they neither dangle nor race (guarded by mutex).
    struct LastResponse {
        std::mutex mutex;
        std::uint8_t return_code = 0;
        std::vector<std::uint8_t> payload;
    };

    std::shared_ptr<LastResponse> last_response_ = std::make_shared<LastResponse>();

    // Bounded subscription lifetime, shared between the vsomeip-thread
    // subscription-status handler (which arms it) and the main-thread onTick
    // (which counts it down and stops the subscription). shared_ptr + mutex so the
    // handler neither dangles nor races, mirroring LastResponse.
    struct SubscriptionLifetime {
        std::mutex mutex;
        bool armed = false;
        int ticks_remaining = 0;
    };

    std::shared_ptr<SubscriptionLifetime> lifetime_ =
        std::make_shared<SubscriptionLifetime>();
};

}  // namespace tc8::dut
