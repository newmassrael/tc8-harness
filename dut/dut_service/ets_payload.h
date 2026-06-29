#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace tc8::dut {

// Copy `len` bytes at `data` into a vector, null-safe: returns an empty vector if
// `data` is null OR `len` is 0. The one fallible piece of inbound marshaling in
// the vsomeip message handlers, kept vsomeip-free (no server/client dependency)
// so it is unit-testable without a live vsomeip message (demo_ets_extension_test)
// and shared by BOTH the server sink and the client control. messageBytes()
// (ets_vsomeip_app.h) wraps this for a vsomeip::message.
inline std::vector<std::uint8_t> payloadBytes(const std::uint8_t* data, std::size_t len) {
    if (data == nullptr || len == 0) {
        return {};
    }
    return std::vector<std::uint8_t>(data, data + len);
}

}  // namespace tc8::dut
