#pragma once

#include <cstdio>
#include <memory>
#include <vector>

#include <CommonAPI/CommonAPI.hpp>
#include <vsomeip/vsomeip.hpp>

#include "ets_payload.h"
#include "ets_reply.h"  // EtsReply (shared reply shape SSOT)

namespace tc8::dut {

// Retrieve the CommonAPI ETS service's OWN vsomeip application — the SINGLE
// SOURCE OF TRUTH for the application-keying contract that BOTH the server sink
// (makeEtsEventSink) and the client control (makeEtsClientControl) depend on.
// CommonAPI's default connection creates the application under
// CommonAPI::DEFAULT_CONNECTION_ID (the empty string), which keys vsomeip's
// application map; the display name (from VSOMEIP_APPLICATION_NAME) never keys
// it, so retrieving by the connection id is mandatory — looking it up by display
// name was the original bug that left the event surface silently disabled.
// Referencing the CommonAPI symbol (not a bare "") keeps this in step if
// CommonAPI ever changes its default connection id. Call only AFTER the CommonAPI
// service is registered (that synchronously creates the application). Returns
// nullptr and logs (parameterised by `role`/`surface`) if not found; the caller
// turns that into its own Null-Object. Internal (vsomeip-aware) — never included
// by an OEM extension TU, which sees only the vsomeip-free seam headers.
inline std::shared_ptr<vsomeip::application> acquireCommonApiApplication(const char* role,
                                                                         const char* surface) {
    auto app = vsomeip::runtime::get()->get_application(CommonAPI::DEFAULT_CONNECTION_ID);
    if (!app) {
        std::fprintf(stderr,
                     "tc8-dut: ETS %s - CommonAPI vsomeip application (default "
                     "connection) not found; OEM %s disabled\n",
                     role, surface);
    }
    return app;
}

// Null-safe extraction of a vsomeip message's payload bytes — the get_payload()
// guard shared by every message handler (onMethod / onRequest / onResponse),
// delegating the raw copy to the vsomeip-free payloadBytes() SSOT.
inline std::vector<std::uint8_t> messageBytes(const std::shared_ptr<vsomeip::message>& msg) {
    const auto pl = msg ? msg->get_payload() : nullptr;
    return payloadBytes(pl ? pl->get_data() : nullptr, pl ? pl->get_length() : 0);
}

// Send `reply` as the SOME/IP reply to `request` on `app` — the SINGLE reply-send
// path shared by the reply-capable seams (IEtsEventSink::onRequestEx and
// IEtsControlChannel::offerControlRequestEx). create_response copies the request's
// Request ID + Interface / Protocol Version and defaults to RESPONSE / E_OK; the
// message type and Return Code are then overridden so the handler can answer with
// an Error message. Those wire fields are raw bytes, so the typed enums map
// straight through a static_cast — including application Return Codes the named
// vsomeip enum does not list.
inline void sendEtsReply(vsomeip::application& app,
                         const std::shared_ptr<vsomeip::message>& request,
                         const EtsReply& reply) {
    auto response = vsomeip::runtime::get()->create_response(request);
    response->set_message_type(
        static_cast<vsomeip::message_type_e>(static_cast<std::uint8_t>(reply.message_type)));
    response->set_return_code(
        static_cast<vsomeip::return_code_e>(static_cast<std::uint8_t>(reply.return_code)));
    response->set_payload(vsomeip::runtime::get()->create_payload(reply.payload));
    app.send(response);
}

}  // namespace tc8::dut
