#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <utility>
#include <vector>

#include "ets_reply.h"        // EtsReply (shared reply shape SSOT)
#include "someip/protocol.h"  // someip::MessageType / ReturnCode (convenience default)

namespace tc8::dut {

// INBOUND control-delivery seam over the DUT's SINGLE vsomeip application — the
// third sibling of IEtsEventSink (server-role event surface) and
// IEtsClientControl (client-role outbound subscribe/call). It exists for ONE
// concern the other two cannot serve: letting a tester drive a CLIENT-only DUT.
//
// In the client-role (CLT) topology the DUT offers no event surface of its own,
// so the server sink's onMethod never receives a Request — there is no offered
// service for the tester's method to land on. This seam offers a SEPARATE control
// service (a distinct id that is NOT a subscribe target) and routes a method on
// it to a handler, giving the tester an inbound channel to drive the DUT's
// client behaviour (e.g. "subscribe to eventgroup X for duration Y") without
// re-offering the subscribe target.
//
// Segregated from IEtsClientControl ON PURPOSE: offer_service is a SERVER verb,
// and a pure outbound-drive (subscribe/call) extension must not depend on
// offer/stop_offer machinery it never uses. Kept vsomeip-free so an OEM TU (and
// the hermetic test) includes only this header; the concrete seam wraps the real
// vsomeip::application (ets_control_channel.cpp), obtained — like makeEtsEventSink
// — by the CommonAPI connection id, so it shares the one routing client (no second
// application). The public default extension never uses it.
// See claudedocs/ets-dut-public-completion-and-oem-seam-design.md.
class IEtsControlChannel {
public:
    virtual ~IEtsControlChannel() = default;

    // Offer a CONTROL service the DUT receives a method Request on while in the
    // CLIENT role, and route `method` to `handler`. `service` MUST differ from
    // every eventgroup target the DUT subscribes to: a local offer of the target
    // would make vsomeip satisfy the subscribe IN-PROCESS and emit no wire
    // SubscribeEventgroup — the exact reason a client-only DUT does not offer the
    // target. Fire-and-forget: the control method drives an action and sends no
    // Response (the shape of the ETS client-control trigger methods); use
    // offerControlRequest / offerControlRequestEx below when the control method
    // must REPLY. offer_service runs once per `(service, instance)` even across
    // several control methods; `method` must not alias a handler registered for the
    // same `(service, instance)` on another seam (they share the one application's
    // handler registry). The handler runs on a vsomeip thread (it must not block);
    // the offer and handler are withdrawn when the channel is destroyed.
    virtual void offerControlMethod(
        std::uint16_t service, std::uint16_t instance, std::uint16_t method,
        std::uint8_t major,
        std::function<void(const std::vector<std::uint8_t>&)> handler) = 0;

    // Offer a REPLY-CAPABLE control method on the control service and route `method`
    // to `handler`, which RETURNS an EtsReply choosing the reply's message type,
    // Return Code, and payload; the DUT echoes the request header onto it and sends
    // the reply. This is the reply complement of offerControlMethod for a
    // CLIENT-only readback: such a DUT offers no server service, so the server
    // sink's onRequestEx has nothing to land on, but this channel already owns the
    // control service the readback can ride. Same offer-once-per-`(service,
    // instance)`, vsomeip-thread (must not block), and withdraw-on-destroy contract.
    virtual void offerControlRequestEx(
        std::uint16_t service, std::uint16_t instance, std::uint16_t method,
        std::uint8_t major,
        std::function<EtsReply(const std::vector<std::uint8_t>&)> handler) = 0;

    // Convenience for the common case: reply with a plain Response (E_OK) whose
    // payload is the handler's returned bytes. Forwards to offerControlRequestEx
    // with a default-typed EtsReply, so the two share the one reply path; reach for
    // offerControlRequestEx directly when the reply must vary the message type or
    // Return Code.
    void offerControlRequest(
        std::uint16_t service, std::uint16_t instance, std::uint16_t method,
        std::uint8_t major,
        std::function<std::vector<std::uint8_t>(const std::vector<std::uint8_t>&)> handler) {
        offerControlRequestEx(
            service, instance, method, major,
            [handler = std::move(handler)](const std::vector<std::uint8_t>& request) {
                return EtsReply{someip::MessageType::RESPONSE,
                                someip::ReturnCode::E_OK, handler(request)};
            });
    }
};

// Build a vsomeip-backed IEtsControlChannel over the CommonAPI ETS service's OWN
// vsomeip application (retrieved by CommonAPI::DEFAULT_CONNECTION_ID, exactly as
// makeEtsEventSink / makeEtsClientControl do). Call only AFTER the application
// exists (registerService or the client-only proxy created it). If the
// application is not found, returns a no-op channel and logs to stderr; never
// returns null, so callers pass `*channel` to the extension hook unconditionally.
// This header stays vsomeip-free; the wrapping lives in ets_control_channel.cpp.
std::unique_ptr<IEtsControlChannel> makeEtsControlChannel();

}  // namespace tc8::dut
