#pragma once

#include <cstdint>
#include <functional>
#include <utility>
#include <vector>

#include "tc8/someip/protocol.h"  // someip::MessageType / ReturnCode

namespace tc8::dut {

// Reply a reply-capable ETS handler returns for a REQUEST it answers: the SOME/IP
// message type and Return Code to send, plus the reply payload. It defaults to a
// plain Response with E_OK, so the common readback sets only `payload` (and the
// seams' plain-Response convenience overloads are exactly that default). Choosing
// ERROR with a non-E_OK Return Code is what lets an OEM method reply with an
// application error the public fidl cannot express (per PRS_SOMEIP_00757 an Error
// must not be E_OK). Shared SSOT for both reply-capable ETS seams — the server
// sink (IEtsEventSink::onRequestEx) and the inbound control channel
// (IEtsControlChannel::offerControlRequestEx).
struct EtsReply {
    someip::MessageType message_type = someip::MessageType::RESPONSE;
    someip::ReturnCode  return_code  = someip::ReturnCode::E_OK;
    std::vector<std::uint8_t> payload;
};

// Adapt a bytes-returning request handler into an EtsReply-returning one whose
// reply is a plain Response (E_OK) carrying those bytes — the common readback
// shape. The single source of the "default reply" adapter shared by the
// reply-capable seams' convenience overloads (IEtsEventSink::onRequest,
// IEtsControlChannel::offerControlRequest), so the default reply is defined once.
inline std::function<EtsReply(const std::vector<std::uint8_t>&)> plainResponse(
    std::function<std::vector<std::uint8_t>(const std::vector<std::uint8_t>&)> handler) {
    return [handler = std::move(handler)](const std::vector<std::uint8_t>& request) {
        return EtsReply{someip::MessageType::RESPONSE, someip::ReturnCode::E_OK,
                        handler(request)};
    };
}

}  // namespace tc8::dut
