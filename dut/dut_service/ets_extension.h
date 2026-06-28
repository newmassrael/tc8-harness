#pragma once

#include <memory>

namespace tc8::dut {

// The event-emission facade an extension offers/notifies through. Defined in
// ets_event_sink.h; forward-declared here because the lifecycle hooks below only
// take it by reference. An OEM extension that USES the sink includes
// ets_event_sink.h for the full definition.
class IEtsEventSink;

// Extend seam (O2 path) for events/methods the OEM owns but that are NOT in the
// public fidl — e.g. the OEM's NDA event surface. The OEM offers them through the
// IEtsEventSink passed to onRegister/onTick (the CommonAPI service's own vsomeip
// application — no second app, no fidl copy). The in-tree default is a no-op so
// the public DUT builds and behaves unchanged. The complementary O1 path is the
// TC8_ETS_FIDL superset-fidl override (CommonAPI-typed). The OEM selects its
// implementation at configure time via TC8_ETS_EXTENSION_SRC — the same
// source-selection idiom as the factory and TC8_ETS_FIDL. See
// claudedocs/ets-dut-public-completion-and-oem-seam-design.md.
//
// Only hooks with a real call site exist (no speculative methods): onRegister
// (after the service is offered — offer events + register method handlers on the
// sink), onTick (each DUT main-loop pass — drive cyclic/duration-windowed
// notifies), onStop (shutdown), ets8001TriggerDriven (queried once before the
// 0x8001 source is registered). A subscribe hook is intentionally absent until
// the DUT has a subscription call site to drive it.
class IEtsExtension {
public:
    virtual ~IEtsExtension() = default;
    virtual void onRegister(IEtsEventSink& sink) { (void)sink; }
    virtual void onTick(IEtsEventSink& sink) { (void)sink; }
    virtual void onStop() {}

    // Whether the OEM build wants TestEventUINT8 (0x8001) to be TRIGGER-driven
    // (armed by triggerEventUINT8, method 0x03) instead of the public default of
    // a free-running 250 ms cyclic source. Default false keeps the public ETS
    // cadence (ETS_086 / ETS_147-151) byte-identical; an OEM DUT whose spec
    // requires 0x8001 only on trigger returns true so its must-NOT-send-0x8001
    // subscribe cases hold. dut_main queries this once, before it registers the
    // 0x8001 emission source, and chooses cyclic vs triggered accordingly.
    virtual bool ets8001TriggerDriven() const { return false; }
};

// Default returns a no-op extension; selected via TC8_ETS_EXTENSION_SRC.
std::unique_ptr<IEtsExtension> createEtsExtension();

}  // namespace tc8::dut
