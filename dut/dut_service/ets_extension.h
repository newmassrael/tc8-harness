#pragma once

#include <memory>

namespace tc8::dut {

// The event-emission facade an extension offers/notifies through. Defined in
// ets_event_sink.h; forward-declared here because the lifecycle hooks below only
// take it by reference. An OEM extension that USES the sink includes
// ets_event_sink.h for the full definition.
class IEtsEventSink;

// The client-role facade an extension drives the DUT's subscribe/RPC surface
// through. Defined in ets_client_control.h; forward-declared here for the same
// by-reference reason. Segregated from IEtsEventSink so an event-only extension
// never depends on the client surface.
class IEtsClientControl;

// The inbound control-delivery facade — offers a control service so a CLIENT-only
// DUT can be driven by the tester. Defined in ets_control_channel.h;
// forward-declared here. Segregated from IEtsClientControl (which is outbound
// subscribe/call) so a pure-drive extension never depends on offer_service.
class IEtsControlChannel;

// The runtime-I/O host — an extension adopts a pollable receiver (e.g. a raw UDP
// receiver the OEM owns and decodes) that the DUT main loop drains. Defined in
// ets_io_host.h; forward-declared here for the same by-reference reason.
// Segregated from the SOME/IP role facades so an extension that needs no raw I/O
// never depends on it.
class IEtsIoHost;

// The collaborators handed to every extension hook: the SERVER-role event sink,
// the CLIENT-role outbound control, the inbound control channel, and the runtime-
// I/O host — all owned by dut_main for the whole run. Bundling them gives every
// hook a uniform, complete context — no "param for the sink but hand-once-and-store
// for the client" asymmetry — and lets a future seam join here without changing any
// hook signature. Holds references (never null); the struct definition only needs
// the forward declarations above.
struct EtsExtensionContext {
    IEtsEventSink& sink;
    IEtsClientControl& client;
    IEtsControlChannel& control;
    IEtsIoHost& io;
};

// Extend seam (O2 path) for events/methods the OEM owns but that are NOT in the
// public fidl — e.g. the OEM's NDA event surface. The OEM offers/handles them and
// drives the DUT's client surface through the EtsExtensionContext passed to every
// hook (the CommonAPI service's own vsomeip application — no second app, no fidl
// copy). The in-tree default is a no-op so the public DUT builds and behaves
// unchanged. The complementary O1 path is the TC8_ETS_FIDL superset-fidl override
// (CommonAPI-typed). The OEM selects its implementation at configure time via
// TC8_ETS_EXTENSION_SRC — the same source-selection idiom as the factory and
// TC8_ETS_FIDL. See claudedocs/ets-dut-public-completion-and-oem-seam-design.md.
//
// Only hooks with a real call site exist (no speculative methods): onRegister
// (after the service is offered — offer events + register method/request handlers
// + wire client subscribe/calls), onReactivate (after a warm suspendInterface
// re-offer — re-apply any re-activation-relative behaviour; fired once per re-offer
// the main loop observes, on the main-loop thread like onRegister/onTick, never on
// the detached suspend thread), onTick (each DUT main-loop pass — drive cyclic/
// duration-windowed notifies), onStop (shutdown), ets8001TriggerDriven (queried once
// before the 0x8001 source is registered).
class IEtsExtension {
public:
    virtual ~IEtsExtension() = default;
    virtual void onRegister(EtsExtensionContext& ctx) { (void)ctx; }
    virtual void onReactivate(EtsExtensionContext& ctx) { (void)ctx; }
    virtual void onTick(EtsExtensionContext& ctx) { (void)ctx; }
    virtual void onStop(EtsExtensionContext& ctx) { (void)ctx; }

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
