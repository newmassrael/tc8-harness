#pragma once

#include <cstdint>
#include <vector>

#include "someip/protocol.h"  // someip::MessageType / ReturnCode

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

}  // namespace tc8::dut
