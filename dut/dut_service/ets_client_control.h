#pragma once

#include <cstdint>
#include <memory>
#include <vector>

namespace tc8::dut {

// Narrow CLIENT-role facade over the DUT's SINGLE vsomeip application — the
// sibling of the server-role IEtsEventSink (ets_event_sink.h). Where the sink
// lets an OEM extension OFFER an event surface (offer/notify/handle), this seam
// lets the extension drive the DUT as a SOME/IP CLIENT: subscribe the DUT to a
// tester-offered eventgroup so vsomeip emits a SubscribeEventgroup SD entry, and
// stop that subscription (StopSubscribe). It is the missing call site the
// client-role (CLT) topology needs — the DUT is the client there, and the
// existing in-tree client paths (the ets3 CommonAPI proxy, the raw-UDP
// FindService runner) target a HARDCODED service/eventgroup, so they cannot
// drive an arbitrary subscribe.
//
// Kept vsomeip-free so an OEM TU (and the hermetic test) includes only this
// header; the concrete seam wraps the real vsomeip::application
// (ets_client_control.cpp), obtained — like makeEtsEventSink — by the CommonAPI
// connection id, so it shares the one routing client (no second application).
// The public default extension never uses it.
//
// Roles are split into two seams ON PURPOSE (interface segregation): an
// event-only OEM extension depends only on IEtsEventSink and never sees this
// client surface. RPC-client drive (a Request + a forwarded-error/last-value
// readback) is a deliberately separate, future addition — this seam is scoped to
// SD/PubSub subscribe only.
// See claudedocs/ets-dut-public-completion-and-oem-seam-design.md.
class IEtsClientControl {
public:
    virtual ~IEtsClientControl() = default;

    // Subscribe the DUT (client role) to `eventgroup` on the tester's
    // `service`/`instance`/`major`. vsomeip requires each event of the eventgroup
    // to be registered before subscribe (else event type/reliability are unknown
    // and notifications are dropped), so `events` lists the eventgroup's event
    // ids and `reliable` selects their transport (true => TCP/RT_RELIABLE, false
    // => UDP/RT_UNRELIABLE). request_service is implied (called internally).
    // vsomeip then emits a SubscribeEventgroup SD entry once the service is
    // found.
    //
    // The wire TTL is governed by vsomeip configuration, NOT this call — vsomeip
    // subscribe() carries no TTL argument. A duration-bounded subscription is
    // realised by the caller arming its own timer and calling
    // stopSubscribeEventgroup() when it expires.
    virtual void subscribeEventgroup(std::uint16_t service, std::uint16_t instance,
                                     std::uint16_t eventgroup,
                                     const std::vector<std::uint16_t>& events,
                                     bool reliable, std::uint8_t major) = 0;

    // Stop the DUT's subscription to `eventgroup` on `service`/`instance`
    // (vsomeip unsubscribe → StopSubscribe, i.e. a SubscribeEventgroup entry with
    // TTL 0). Safe to call for a subscription that was never started (no-op).
    virtual void stopSubscribeEventgroup(std::uint16_t service, std::uint16_t instance,
                                         std::uint16_t eventgroup) = 0;
};

// Build a vsomeip-backed IEtsClientControl over the CommonAPI ETS service's OWN
// vsomeip application (retrieved by CommonAPI::DEFAULT_CONNECTION_ID, exactly as
// makeEtsEventSink does — see its header for why the connection id, not the
// display name, keys the application map). Call only AFTER the CommonAPI service
// is registered (that synchronously creates the application). If the application
// is not found, returns a no-op control and logs to stderr; never returns null,
// so callers pass `*control` to the extension hook unconditionally. This header
// stays vsomeip-free; the wrapping lives in ets_client_control.cpp.
std::unique_ptr<IEtsClientControl> makeEtsClientControl();

}  // namespace tc8::dut
