#include "tc8/autosar/crc.h"

namespace tc8::crc {
namespace {
constexpr std::uint8_t kCrc8Xor = 0xFF;   // SAE-J1850 initial value and final XOR
}  // namespace

std::uint8_t crc8SaeJ1850(const std::uint8_t* data, std::size_t len,
                          std::uint8_t start_value, bool is_first_call) {
    // Resume re-applies the final XOR (start_value ^ 0xFF) so chained calls equal
    // one pass; the first call starts from the 0xFF initial value.
    std::uint8_t crc =
        is_first_call ? kCrc8Xor : static_cast<std::uint8_t>(start_value ^ kCrc8Xor);
    for (std::size_t i = 0; i < len; ++i) {
        crc = static_cast<std::uint8_t>(crc ^ data[i]);
        for (int bit = 0; bit < 8; ++bit) {
            if (crc & 0x80U) {
                crc = static_cast<std::uint8_t>((crc << 1) ^ 0x1DU);
            } else {
                crc = static_cast<std::uint8_t>(crc << 1);
            }
        }
    }
    return static_cast<std::uint8_t>(crc ^ kCrc8Xor);
}

std::uint16_t crc16Ccitt(const std::uint8_t* data, std::size_t len,
                         std::uint16_t start_value, bool is_first_call) {
    // CCITT-FALSE has no final XOR, so resuming is simply the prior return value.
    std::uint16_t crc = is_first_call ? 0xFFFF : start_value;
    for (std::size_t i = 0; i < len; ++i) {
        crc = static_cast<std::uint16_t>(crc ^ (static_cast<std::uint16_t>(data[i]) << 8));
        for (int bit = 0; bit < 8; ++bit) {
            if (crc & 0x8000U) {
                crc = static_cast<std::uint16_t>((crc << 1) ^ 0x1021U);
            } else {
                crc = static_cast<std::uint16_t>(crc << 1);
            }
        }
    }
    return crc;
}

}  // namespace tc8::crc
