#pragma once

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "tc8/someip/protocol.h"

namespace tc8::someip {

// SOME/IP wire-encoding primitives shared by the tester builders (src/stimulus)
// AND the tc8-dut firmware (dut/dut_service). Header-only by design: including
// this creates a compile-time dependency, NOT a link edge, so the firmware's
// "no reverse dependency on the harness library" rule is satisfied while the
// 16-byte header layout and big-endian helpers live in ONE place rather than
// being hand-respelled per builder.

// Network byte order (big-endian) integer readers — the inverse of the putBeNN
// appenders below. Used by every wire PARSER (the SOME/IP header decode here, the
// dissector, and the tester-side responders that read L2-L4 fields) so the
// reader side shares one definition rather than re-spelling `(p[0]<<8)|p[1]` per
// translation unit, exactly as the writers already do. `p` must point at >= 2 (16)
// or >= 4 (32) readable bytes — callers bounds-check before calling.
inline std::uint16_t getBe16(const std::uint8_t *p) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8) | p[1]);
}

inline std::uint32_t getBe32(const std::uint8_t *p) {
    return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
}

// Network byte order (big-endian) appenders for the SOME/IP wire format.
inline void putBe16(std::vector<std::uint8_t> &b, std::uint16_t v) {
    b.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
    b.push_back(static_cast<std::uint8_t>(v & 0xFF));
}

inline void putBe24(std::vector<std::uint8_t> &b, std::uint32_t v) {
    // The wire field is exactly 3 bytes; the SD TTL and Reserved fields are
    // both 24-bit, so a value above 24 bits is a caller bug, not a value to
    // silently truncate. Assert in debug; a release build keeps the low-24
    // write (no behaviour change to conformant callers, all of which pass
    // <= 0xFFFFFF).
    assert((v >> 24) == 0 && "putBe24: value exceeds 24 bits");
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

// The fixed SOME/IP header size (bytes 0..15). Both appendHeader (which emits
// exactly this many) and parseHeader read/write within it.
inline constexpr std::size_t kHeaderSize = 16;

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

// Decode the 16-byte SOME/IP header at `data` into `out` — the READER inverse of
// appendHeader, so the field layout has ONE source of truth for both directions.
// Returns false (leaving `out` untouched) if `data` is null or `len` < kHeaderSize.
// `message_type` / `return_code` are raw bytes (as in Header / appendHeader), so a
// deliberately-malformed off-enum value round-trips rather than being clamped. The
// `length` field is returned as-is; callers that need the datagram bound validate
// it themselves (it is not trusted here).
inline bool parseHeader(const std::uint8_t *data, std::size_t len, Header &out) {
    if (data == nullptr || len < kHeaderSize) {
        return false;
    }
    out.service_id = getBe16(data + 0);
    out.method_id = getBe16(data + 2);
    out.length = getBe32(data + 4);
    out.client_id = getBe16(data + 8);
    out.session_id = getBe16(data + 10);
    out.protocol_version = data[12];
    out.interface_version = data[13];
    out.message_type = data[14];
    out.return_code = data[15];
    return true;
}

}  // namespace tc8::someip
