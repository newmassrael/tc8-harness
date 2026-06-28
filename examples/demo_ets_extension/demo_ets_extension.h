#pragma once

#include <cstdint>
#include <vector>

#include "ets_event_sink.h"  // IEtsEventSink
#include "ets_extension.h"   // IEtsExtension

namespace tc8::dut {

// Synthetic, NON-NDA demonstration of the IEtsExtension seam — a copy-paste
// starter an OEM adapts to offer its OWN (NDA) event surface on the shared
// vsomeip application, selected at configure time via TC8_ETS_EXTENSION_SRC (see
// demo_ets_extension.cpp). It exercises all three IEtsEventSink facade methods:
// offerEvent + onMethod in onRegister, and notify from the registered trigger.
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

// Header-only so the hermetic test can instantiate it directly (no link step)
// and the OEM can subclass/adapt it inline.
class DemoEtsExtension : public IEtsExtension {
public:
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
    }
};

}  // namespace tc8::dut
