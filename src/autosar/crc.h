#pragma once

#include <cstddef>
#include <cstdint>

namespace tc8::crc {

// AUTOSAR CRC Routines (SWS Crc) — the vendor-neutral CRC primitives the E2E
// profiles build on. Kept as their own module because CRC is a shared building
// block (E2E, and potentially Com/SecOC): folding it into one consumer would
// force the next consumer to either re-implement it or reach into the first.
//
// The signature mirrors AUTOSAR Crc_CalculateCRCx so a multi-segment CRC (as the
// E2E profiles need — Data ID then data) is a faithful transcription rather than
// a re-derived shortcut:
//   * is_first_call == true  -> start from the algorithm's initial value;
//     start_value is ignored (AUTOSAR contract).
//   * is_first_call == false -> resume a running CRC from start_value (a prior
//     return), re-applying the final XOR internally so chained calls equal one
//     pass over the concatenated data.
// Both are MSB-first with no input/output reflection. `data` may be null when
// `len` is 0.

// CRC-8/SAE-J1850 == AUTOSAR Crc_CalculateCRC8: polynomial 0x1D, initial value
// 0xFF, final XOR 0xFF. Catalog check over "123456789" (start 0, first call) is
// 0x4B. Used by E2E Profile 11 (and Profile 1).
std::uint8_t crc8SaeJ1850(const std::uint8_t* data, std::size_t len,
                          std::uint8_t start_value, bool is_first_call);

// CRC-16/CCITT-FALSE == AUTOSAR Crc_CalculateCRC16: polynomial 0x1021, initial
// value 0xFFFF, no final XOR. Catalog check over "123456789" (start 0, first
// call) is 0x29B1. Used by E2E Profile 5.
std::uint16_t crc16Ccitt(const std::uint8_t* data, std::size_t len,
                         std::uint16_t start_value, bool is_first_call);

}  // namespace tc8::crc
