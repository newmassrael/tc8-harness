#pragma once

#include <cstdint>
#include <vector>

#include "tc8/someip/protocol.h"

namespace tc8::dut {

// Fields of a DUT-side (client-role) SOME/IP Method Request. Firmware-local
// (mirrors the tester's tc8::stimulus::SomeIpRpcMessage) so tc8-dut carries
// named-field safety without linking the harness/tester library. `message_type`
// is the typed enum — someip/protocol.h is a header-only leaf the firmware may
// include (no link edge) — so the caller drives Request / RequestNoReturn
// without a raw magic byte.
struct MethodCall {
    std::uint16_t service_id = 0;
    std::uint16_t method_id = 0;
    std::uint16_t client_id = 0;
    std::uint16_t session_id = 0;
    someip::MessageType message_type = someip::MessageType::REQUEST;
    std::vector<std::uint8_t> payload{};
};

// The datagram the DUT sends when it calls a method on the tester's offered
// service (DUT in client role). Builds the 16-byte SOME/IP header via someip::appendHeader
// — the shared wire SSOT, so the firmware and the tester's buildMethodRequest
// cannot drift — plus the payload. Length field = 8 + payload.size() (Request ID
// through the end); return_code is E_OK and protocol/interface version are 0x01.
std::vector<std::uint8_t> buildMethodRequestWire(const MethodCall &call);

}  // namespace tc8::dut
