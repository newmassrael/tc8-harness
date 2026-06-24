#pragma once

#include <cstddef>
#include <cstdint>

namespace tc8::crc {

// AUTOSAR CRC Routines (SWS Crc) — the vendor-neutral CRC primitives the E2E
// profiles build on. Kept as their own module because CRC is a shared building
// block (E2E, and potentially Com/SecOC): folding it into one consumer would
// force the next consumer to either re-implement it or reach into the first.
//
// Both are computed MSB-first with no input/output reflection. `data` may be
// null only when `len` is 0.

// CRC-8/SAE-J1850 == AUTOSAR Crc_CalculateCRC8: polynomial 0x1D, initial value
// 0xFF, final XOR 0xFF. The catalog check value over the ASCII bytes
// "123456789" is 0x4B. Used by E2E Profile 11 (and Profile 1).
std::uint8_t crc8SaeJ1850(const std::uint8_t* data, std::size_t len);

// CRC-16/CCITT-FALSE == AUTOSAR Crc_CalculateCRC16: polynomial 0x1021, initial
// value 0xFFFF, no final XOR. The catalog check value over "123456789" is
// 0x29B1. Used by E2E Profile 5.
std::uint16_t crc16Ccitt(const std::uint8_t* data, std::size_t len);

}  // namespace tc8::crc
