#pragma once

#include <cstdint>
#include <vector>

#include "someip/protocol.h"

namespace tc8::someip {

// SOME/IP wire-encoding primitives shared by the tester builders (src/stimulus)
// AND the tc8-dut firmware (dut/dut_service). Header-only by design: including
// this creates a compile-time dependency, NOT a link edge, so the firmware's
// "no reverse dependency on the harness library" rule is satisfied while the
// 16-byte header layout and big-endian helpers live in ONE place rather than
// being hand-respelled per builder.

// Network byte order (big-endian) appenders for the SOME/IP wire format.
inline void putBe16(std::vector<std::uint8_t> &b, std::uint16_t v) {
    b.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
    b.push_back(static_cast<std::uint8_t>(v & 0xFF));
}

inline void putBe24(std::vector<std::uint8_t> &b, std::uint32_t v) {
    b.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFF));
    b.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
    b.push_back(static_cast<std::uint8_t>(v & 0xFF));
}

inline void putBe32(std::vector<std::uint8_t> &b, std::uint32_t v) {
    b.push_back(static_cast<std::uint8_t>((v >> 24) & 0xFF));
    b.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFF));
    b.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
    b.push_back(static_cast<std::uint8_t>(v & 0xFF));
}

// The 16-byte SOME/IP header. `message_type` / `return_code` are raw
// bytes (not the MessageType / ReturnCode enums) so a caller can drive an
// off-enum value for a deliberately-malformed frame; valid callers fill them
// from the enums via static_cast. `length` counts bytes from Request ID
// through the end of the payload.
struct Header {
    std::uint16_t service_id = 0;
    std::uint16_t method_id = 0;
    std::uint32_t length = 0;
    std::uint16_t client_id = 0;
    std::uint16_t session_id = 0;
    std::uint8_t protocol_version = 0x01;
    std::uint8_t interface_version = 0x01;
    std::uint8_t message_type = static_cast<std::uint8_t>(MessageType::REQUEST);
    std::uint8_t return_code = static_cast<std::uint8_t>(ReturnCode::E_OK);
};

// Append the 16-byte SOME/IP header to `b`. The single source of the header
// wire layout — every SOME/IP builder (RPC, SD, firmware) routes through here.
inline void appendHeader(std::vector<std::uint8_t> &b, const Header &h) {
    putBe16(b, h.service_id);
    putBe16(b, h.method_id);
    putBe32(b, h.length);
    putBe16(b, h.client_id);
    putBe16(b, h.session_id);
    b.push_back(h.protocol_version);
    b.push_back(h.interface_version);
    b.push_back(h.message_type);
    b.push_back(h.return_code);
}

}  // namespace tc8::someip
