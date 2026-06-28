#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

namespace tc8::dut {

// Narrow registration facade over the DUT's SINGLE vsomeip application, handed to
// the OEM extension via onRegister/onTick. It lets the extension add an NDA event
// surface — offer additional events, notify subscribers, handle trigger methods —
// on the SAME application the CommonAPI ETS service already uses, so there is NO
// second vsomeip application (no coexisting routing client) and NO copy of the
// public fidl. Kept vsomeip-free so an OEM TU implementing IEtsExtension includes
// only this header; the concrete sink (ets_event_sink.h) wraps the real
// vsomeip::application, obtained by name. The public default extension never uses
// it. See claudedocs/ets-dut-public-completion-and-oem-seam-design.md.
class IEtsEventSink {
public:
    virtual ~IEtsEventSink() = default;

    // Offer `event_id` on the ETS service for `eventgroups` (vsomeip offer_event,
    // ET_EVENT). Call once per event before notify(); the events the OEM owns are
    // NOT in the public fidl, so CommonAPI does not offer them.
    virtual void offerEvent(std::uint16_t event_id,
                            const std::vector<std::uint16_t>& eventgroups) = 0;

    // Notify current subscribers of `event_id` with `payload` (vsomeip notify).
    // offerEvent(event_id, ...) must have been called first.
    virtual void notify(std::uint16_t event_id,
                        const std::vector<std::uint8_t>& payload) = 0;

    // Register `handler` for incoming requests to `method_id`; the handler
    // receives the request payload bytes. For the OEM fireAndForget trigger
    // methods (no response is sent).
    virtual void onMethod(std::uint16_t method_id,
                          std::function<void(const std::vector<std::uint8_t>&)> handler) = 0;
};

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
