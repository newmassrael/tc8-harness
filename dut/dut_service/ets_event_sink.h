#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

namespace tc8::dut {

// Narrow registration facade over the DUT's SINGLE vsomeip application, handed to
// an OEM IEtsExtension via onRegister/onTick (see ets_extension.h). It lets the
// extension add an NDA event surface — offer additional events, notify
// subscribers, handle trigger methods — on the SAME application the CommonAPI ETS
// service already uses, so there is NO second vsomeip application (no coexisting
// routing client) and NO copy of the public fidl. Kept vsomeip-free so an OEM TU
// includes only this header; the concrete sink wraps the real
// vsomeip::application (ets_event_sink.cpp), obtained by the CommonAPI connection
// id. The public default extension never uses it.
// See claudedocs/ets-dut-public-completion-and-oem-seam-design.md.
class IEtsEventSink {
public:
    virtual ~IEtsEventSink() = default;

    // Offer `event_id` on the ETS service for `eventgroups` (vsomeip offer_event,
    // ET_EVENT). Call once per event before notify(); the events the OEM owns are
    // NOT in the public fidl, so CommonAPI does not offer them. One or more
    // eventgroups is valid.
    virtual void offerEvent(std::uint16_t event_id,
                            const std::vector<std::uint16_t>& eventgroups) = 0;

    // Notify current subscribers of `event_id` with `payload` (vsomeip notify).
    // offerEvent(event_id, ...) must have been called first.
    virtual void notify(std::uint16_t event_id,
                        const std::vector<std::uint8_t>& payload) = 0;

    // Register `handler` for incoming requests to `method_id`; the handler
    // receives the request payload bytes. For the OEM fireAndForget trigger
    // methods (no response is sent). The handler runs on a vsomeip thread, so it
    // must not outlive the sink — the concrete sink unregisters its handlers on
    // destruction so a captured `&sink` cannot dangle (see ets_event_sink.cpp).
    virtual void onMethod(std::uint16_t method_id,
                          std::function<void(const std::vector<std::uint8_t>&)> handler) = 0;

    // Register a REQUEST/RESPONSE `handler` for `method_id`: the handler receives
    // the request payload and RETURNS the response payload, which the DUT sends
    // back as a SOME/IP Response (return code E_OK). This is the complement of
    // onMethod (fire-and-forget) for OEM methods that must REPLY — e.g. a
    // last-error / last-value readback that is not in the public fidl, so
    // CommonAPI does not serve it. Same vsomeip-thread + unregister-on-destroy
    // contract as onMethod.
    virtual void onRequest(
        std::uint16_t method_id,
        std::function<std::vector<std::uint8_t>(const std::vector<std::uint8_t>&)> handler) = 0;
};

// Build a vsomeip-backed IEtsEventSink over the CommonAPI ETS service's OWN
// vsomeip application, so the extension shares the one routing client (no second
// vsomeip application). The application is retrieved from the runtime by the
// CommonAPI connection id (CommonAPI::DEFAULT_CONNECTION_ID, the empty string),
// because registerService uses CommonAPI's default connection and vsomeip keys
// its application map by that create-time id. The app's display name (from
// VSOMEIP_APPLICATION_NAME / kApplicationName) never keys the map, so it must NOT
// be used to retrieve the application — that was the original bug. Events and
// method handlers are scoped to `service`/`instance`. Call only AFTER the
// CommonAPI service is registered (that synchronously creates the application).
//
// If the application is not found, returns a no-op sink and logs to stderr — the
// public DUT, whose default extension never uses the sink, is unaffected. Never
// returns null, so callers pass `*sink` to the extension hooks unconditionally.
//
// This header stays vsomeip-free; the wrapping of vsomeip::application lives in
// ets_event_sink.cpp.
std::unique_ptr<IEtsEventSink> makeEtsEventSink(std::uint16_t service,
                                                std::uint16_t instance);

}  // namespace tc8::dut
