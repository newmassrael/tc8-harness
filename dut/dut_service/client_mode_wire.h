#pragma once

#include <cstdint>
#include <vector>

namespace tc8::dut {

// DUT-side (client-role) SOME/IP Method Request datagram for the SOMEIPCLT
// scenarios — the wire the DUT sends when it calls a method on the tester's
// offered service. Hand-built (mirrors tc8::stimulus::buildMethodRequest at
// src/stimulus/someip_rpc_builder.cpp) and kept in the firmware module so
// tc8-dut does not link the harness/tester library — the same reverse-direction
// dependency avoidance documented on buildFindServiceWire (client_mode.cpp).
//
// Length field = 8 + payload.size() (bytes from Request ID through the end);
// return_code is E_OK (0x00) and protocol/interface version are 0x01 per the
// SOME/IP header layout. `message_type` is explicit so the caller drives
// Request (0x00) or RequestNoReturn (0x01).
std::vector<std::uint8_t> buildMethodRequestWire(std::uint16_t service_id, std::uint16_t method_id,
                                                 std::uint16_t client_id, std::uint16_t session_id,
                                                 std::uint8_t message_type,
                                                 const std::vector<std::uint8_t> &payload);

}  // namespace tc8::dut
