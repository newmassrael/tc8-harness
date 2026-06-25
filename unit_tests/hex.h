#pragma once

#include <cstdint>
#include <string>

namespace tc8::test {

// Lowercase hex of any byte range (std::array / std::vector<std::uint8_t>) so a
// vector mismatch prints the actual vs expected bytes rather than opaque arrays.
// Shared by the engine tests (CRC/CMAC/E2E/COM) to keep one hex helper.
template <class Bytes>
std::string toHex(const Bytes& bytes) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    for (std::uint8_t b : bytes) {
        out.push_back(digits[b >> 4]);
        out.push_back(digits[b & 0x0FU]);
    }
    return out;
}

}  // namespace tc8::test
