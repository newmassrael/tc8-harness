#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace tc8::dut {

// Narrow registration facade over the DUT's SINGLE vsomeip application, handed to
// an OEM IEtsExtension via onRegister/onTick (see ets_extension.h). It lets the
// extension add an NDA event surface — offer additional events, notify
// subscribers, handle trigger methods — on the SAME application the CommonAPI ETS
// service already uses, so there is NO second vsomeip application (no coexisting
// routing client) and NO copy of the public fidl. Kept vsomeip-free so an OEM TU
// includes only this header; the concrete sink wraps the real
// vsomeip::application (ets_event_sink.cpp), obtained by name. The public default
// extension never uses it. See claudedocs/ets-dut-public-completion-and-oem-seam-design.md.
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
};

// Build a vsomeip-backed IEtsEventSink over the CommonAPI ETS service's OWN
// vsomeip application, so the extension shares the one routing client (no second
// vsomeip application). The application is retrieved from the runtime by the
// CommonAPI connection id, NOT by display name: registerService uses CommonAPI's
// default connection, whose id is the empty string, so vsomeip keys the app under
// "" (its display name resolving from VSOMEIP_APPLICATION_NAME is a separate
// concern that never keys the map). `app_name` is only a fallback for a
// non-default named connection. Events and method handlers are scoped to
// `service`/`instance`. Call only AFTER the CommonAPI service is registered (that
// synchronously creates the application).
//
// If the application is not found, returns a no-op sink and logs to stderr — the
// public DUT, whose default extension never uses the sink, is unaffected. Never
// returns null, so callers pass `*sink` to the extension hooks unconditionally.
//
// This header stays vsomeip-free; the wrapping of vsomeip::application lives in
// ets_event_sink.cpp.
std::unique_ptr<IEtsEventSink> makeEtsEventSink(const std::string& app_name,
                                                std::uint16_t service,
                                                std::uint16_t instance);

// Copy `len` bytes at `data` into a vector, null-safe: returns an empty vector if
// `data` is null OR `len` is 0. The one fallible piece of inbound marshaling in
// VsomeipEtsEventSink::onMethod, kept here as an inline (vsomeip-free) function so
// it is unit-testable without a live vsomeip message (demo_ets_extension_test.cpp)
// and reused by the message-handler closure (ets_event_sink.cpp).
inline std::vector<std::uint8_t> payloadBytes(const std::uint8_t* data, std::size_t len) {
    if (data == nullptr || len == 0) {
        return {};
    }
    return std::vector<std::uint8_t>(data, data + len);
}

}  // namespace tc8::dut
