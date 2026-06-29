#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <vector>

#include "ets_client_control.h"  // IEtsClientControl
#include "ets_event_sink.h"      // IEtsEventSink
#include "ets_extension.h"       // IEtsExtension

namespace tc8::dut {

// Synthetic, NON-NDA demonstration of the IEtsExtension seam — a copy-paste
// starter an OEM adapts to offer its OWN (NDA) surface on the shared vsomeip
// application, selected at configure time via TC8_ETS_EXTENSION_SRC (see
// demo_ets_extension.cpp). It exercises the SERVER-role IEtsEventSink (offerEvent
// + onMethod + the reply-capable onRequest) AND the CLIENT-role
// IEtsClientControl (subscribe/stop, plus an RPC call whose Response it captures)
// — the client-role (CLT) topology shape: the tester drives a method, the DUT
// subscribes or calls back, and a readback method replies with what it observed.
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

// Header-only so the hermetic test can instantiate it directly (no link step)
// and the OEM can subclass/adapt it inline.
class DemoEtsExtension : public IEtsExtension {
public:
    // Store the client-role facade, handed once before onRegister, so the
    // subscribe-method handler and onStop can drive the DUT's client surface.
    void onRegisterClientControl(IEtsClientControl& client) override {
        client_ = &client;
    }

    void onRegister(IEtsEventSink& sink) override {
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

        // CLIENT demo: when the tester Requests kDemoSubscribeMethod, drive the
        // DUT to subscribe (UDP) to the synthetic target eventgroup. Capture the
        // facade POINTER by value (valid from onRegisterClientControl, which runs
        // first) instead of `this`, so the vsomeip-thread handler holds no
        // reference to this extension — the same lifetime discipline as `&sink`.
        IEtsClientControl* client = client_;
        sink.onMethod(kDemoSubscribeMethod,
                      [client](const std::vector<std::uint8_t>&) {
                          if (client != nullptr) {
                              client->subscribeEventgroup(
                                  kDemoTargetService, kDemoTargetInstance,
                                  kDemoTargetEventgroup, {kDemoTargetEvent},
                                  /*reliable=*/false, kDemoTargetMajor);
                          }
                      });

        // RPC-CLIENT demo: capture the target method's Response into shared state,
        // call it on kDemoCallMethod, and reply with the captured payload on the
        // readback Request. The closures capture a COPY of the shared_ptr (not
        // `this`), so the response handler (a vsomeip thread) and the readback
        // reply (another) safely outlive this extension and serialise on the
        // state's mutex — the cross-thread pattern an OEM readback needs.
        if (client != nullptr) {
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
    }

    // Stop the demo subscription on shutdown. Runs on the DUT main thread (not a
    // vsomeip handler), so it may touch client_ directly. Safe even if the
    // subscribe method was never Requested — stopSubscribeEventgroup is a no-op
    // for an unknown subscription.
    void onStop() override {
        if (client_ != nullptr) {
            client_->stopSubscribeEventgroup(kDemoTargetService, kDemoTargetInstance,
                                             kDemoTargetEventgroup);
        }
    }

private:
    // Last Response observed for the target method, shared with the vsomeip-thread
    // handlers via shared_ptr so they neither dangle nor race (guarded by mutex).
    struct LastResponse {
        std::mutex mutex;
        std::uint8_t return_code = 0;
        std::vector<std::uint8_t> payload;
    };

    IEtsClientControl* client_ = nullptr;
    std::shared_ptr<LastResponse> last_response_ = std::make_shared<LastResponse>();
};

}  // namespace tc8::dut
