#include "autosar/crc.h"

namespace tc8::crc {

std::uint8_t crc8SaeJ1850(const std::uint8_t* data, std::size_t len) {
    std::uint8_t crc = 0xFF;
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
    return static_cast<std::uint8_t>(crc ^ 0xFFU);
}

std::uint16_t crc16Ccitt(const std::uint8_t* data, std::size_t len) {
    std::uint16_t crc = 0xFFFF;
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
