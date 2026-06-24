#include <cstddef>
#include <cstdint>
#include <vector>

#include <gtest/gtest.h>

#include "autosar/crc.h"

namespace tc8::crc {
namespace {

// The CRC catalog "check" value is the CRC of the nine ASCII bytes "123456789"
// and is the standard, published external reference for a CRC definition.
// Matching it pins the polynomial, init value, reflection, and final XOR — so
// whatever these routines then return for other inputs is correct by
// construction (this is the external anchor the E2E round-trip tests lack).
const std::vector<std::uint8_t> kCheck = {'1', '2', '3', '4', '5', '6', '7', '8', '9'};

TEST(Crc8SaeJ1850, CatalogCheckValue) {
    EXPECT_EQ(crc8SaeJ1850(kCheck.data(), kCheck.size()), 0x4B);
}

TEST(Crc16Ccitt, CatalogCheckValue) {
    EXPECT_EQ(crc16Ccitt(kCheck.data(), kCheck.size()), 0x29B1);
}

// Empty input returns the initial value with the final XOR applied: CRC-8 is
// 0xFF ^ 0xFF = 0x00; CRC-16 is 0xFFFF with no final XOR. Also exercises the
// null-at-zero-length contract.
TEST(Crc8SaeJ1850, EmptyInput) {
    EXPECT_EQ(crc8SaeJ1850(nullptr, 0), 0x00);
}

TEST(Crc16Ccitt, EmptyInput) {
    EXPECT_EQ(crc16Ccitt(nullptr, 0), 0xFFFF);
}

}  // namespace
}  // namespace tc8::crc
