#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

namespace tc8::dut {

// Narrow CLIENT-role facade over the DUT's SINGLE vsomeip application — the
// sibling of the server-role IEtsEventSink (ets_event_sink.h). Where the sink
// lets an OEM extension OFFER an event surface (offer/notify/handle), this seam
// lets the extension drive the DUT as a SOME/IP CLIENT: subscribe the DUT to a
// tester-offered eventgroup (so vsomeip emits a SubscribeEventgroup SD entry) and
// stop that subscription (StopSubscribe), and issue an RPC Request to a tester
// method and capture its Response/Error. It is the missing call site the
// client-role (CLT) topology needs — the DUT is the client there, and the
// existing in-tree client paths (the ets3 CommonAPI proxy, the raw-UDP
// FindService runner) target a HARDCODED service/eventgroup, so they cannot
// drive an arbitrary subscribe or call.
//
// Kept vsomeip-free so an OEM TU (and the hermetic test) includes only this
// header; the concrete seam wraps the real vsomeip::application
// (ets_client_control.cpp), obtained — like makeEtsEventSink — by the CommonAPI
// connection id, so it shares the one routing client (no second application).
// The public default extension never uses it.
//
// Roles are split from IEtsEventSink ON PURPOSE (interface segregation): an
// event-only OEM extension depends only on IEtsEventSink and never sees this
// client surface. The complement on the SERVER seam is IEtsEventSink::onRequest
// (the DUT REPLIES to a tester Request — e.g. an OEM last-error / last-value
// readback), which a client-role extension pairs with onResponse here.
// See claudedocs/ets-dut-public-completion-and-oem-seam-design.md.
class IEtsClientControl {
public:
    virtual ~IEtsClientControl() = default;

    // Trigger the DUT (client role) to DISCOVER `service`/`instance` at interface
    // `major` by request_service()ing it: vsomeip's SD client then emits a
    // FindService SD entry carrying `major` through the Initial-Wait and Repetition
    // phases (a not-yet-available remote service is exactly what makes vsomeip Find —
    // see requestServiceLocked, "request_service only STARTS the SD FindService").
    // This is the pure-discovery sibling of subscribeEventgroup/callMethod (which
    // request_service internally) — no eventgroup, no method, just the Find — for a
    // verdict that observes the emitted FindService's Major. Pass major == 0xFF
    // (vsomeip::ANY_MAJOR) to Find with no version preference (the wildcard Find), or
    // a specific value to Find that Major. The requested minor is ANY_MINOR (a
    // SOME/IP-SD Find carries no specific minor). Idempotent per (service, instance):
    // vsomeip request_service dedups, so the Major is fixed at the first findService
    // for a pair; the dtor's release_service balances it once. Using this instead of
    // the CommonAPI ClientTarget proxy is what keeps the wire to a SINGLE Find at the
    // chosen Major (the proxy would emit its own fixed-Major Find in parallel).
    virtual void findService(std::uint16_t service, std::uint16_t instance,
                             std::uint8_t major) = 0;

    // Subscribe the DUT (client role) to `eventgroup` on the tester's
    // `service`/`instance`/`major`. vsomeip requires each event of the eventgroup
    // to be registered before subscribe (else event type/reliability are unknown
    // and notifications are dropped), so `events` lists the eventgroup's event
    // ids and `reliable` selects their transport (true => TCP/RT_RELIABLE, false
    // => UDP/RT_UNRELIABLE). request_service is implied (called internally).
    // vsomeip then emits a SubscribeEventgroup SD entry once the service is
    // found. PRECONDITION: `events` MUST be non-empty — with no registered event
    // vsomeip's discovery sends NO SubscribeEventgroup entry (the implementation
    // guards this and logs rather than silently no-op).
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

    // Observe the status of the DUT's OWN subscription to `eventgroup` on
    // `service`/`instance` as a SINGLE clean edge: `handler` is invoked with
    // `established == true` once when the subscription takes effect (the tester's
    // SubscribeEventgroupAck) and with `established == false` if it is later
    // rejected/lost (a Nack). vsomeip reports status per event of the eventgroup;
    // the seam collapses that to one edge — the consumer is told only on an actual
    // transition, never repeatedly for the same state. A client-role extension
    // uses the established edge to anchor a subscription-lifetime timer to the
    // instant the subscription ACTUALLY took effect — not to DUT startup, which
    // races the tester's OfferService and would misalign the lifetime window.
    // Register this BEFORE subscribeEventgroup() so the Ack cannot arrive before
    // the handler is in place. The handler runs on a vsomeip thread (it must not
    // block) and is unregistered when the control is destroyed, so a captured
    // reference cannot dangle.
    virtual void onSubscriptionStatus(
        std::uint16_t service, std::uint16_t instance, std::uint16_t eventgroup,
        std::function<void(bool established)> handler) = 0;

    // Send a SOME/IP Request from the DUT (client role) to `method` on the
    // tester's `service`/`instance`/`major`, with `payload`, over UDP
    // (reliable=false) or TCP (reliable=true). request_service is implied.
    //
    // Timing-robust: if the service is not yet available (its SD OfferService has
    // not arrived), the Request is HELD and sent automatically once the service
    // becomes available, so a single callMethod() at trigger time reaches the wire
    // regardless of where discovery stands — the caller sequences no warm-up and
    // no separate priming step. This mirrors subscribeEventgroup, which vsomeip
    // re-applies on availability; a one-shot send would otherwise be DROPPED (not
    // queued) against a not-yet-discovered service. Held Requests are flushed in
    // call order. The Response/Error arrives asynchronously and is delivered to a
    // handler registered with onResponse() for the same
    // `service`/`instance`/`method`.
    virtual void callMethod(std::uint16_t service, std::uint16_t instance,
                            std::uint16_t method,
                            const std::vector<std::uint8_t>& payload, bool reliable,
                            std::uint8_t major) = 0;

    // Fire & Forget variant of callMethod: issues the Request as a REQUEST_NO_RETURN
    // (message_type 0x01) instead of a REQUEST (0x00), so the tester sends no Response
    // and the DUT registers no onResponse for it. Same arguments and the SAME
    // timing-robust hold-until-available behavior as callMethod — the message type is
    // fixed before the Request is held, so a queued F&F flushes with the right type.
    // Use when the verdict asserts the client emitted a no-return Request.
    virtual void callMethodNoReturn(std::uint16_t service, std::uint16_t instance,
                                    std::uint16_t method,
                                    const std::vector<std::uint8_t>& payload,
                                    bool reliable, std::uint8_t major) = 0;

    // Register `handler` for Responses AND Errors to `method` on
    // `service`/`instance` — the reaction surface a client-role verdict observes
    // (return code + payload, "last received" semantics). The handler runs on a
    // vsomeip thread, so it must not block; it is unregistered when the control
    // is destroyed so a captured reference cannot dangle.
    virtual void onResponse(
        std::uint16_t service, std::uint16_t instance, std::uint16_t method,
        std::function<void(std::uint8_t return_code,
                           const std::vector<std::uint8_t>& payload)> handler) = 0;
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
