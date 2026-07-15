#include <cstddef>
#include <cstdint>
#include <vector>

#include <gtest/gtest.h>

#include "tc8/autosar/crc.h"

namespace tc8::crc {
namespace {

// The CRC catalog "check" value is the CRC of the nine ASCII bytes "123456789"
// and is the standard, published external reference for a CRC definition.
// Matching it pins the polynomial, init value, reflection, and final XOR — so
// whatever these routines then return for other inputs is correct by
// construction (this is the external anchor the E2E round-trip tests lack).
const std::vector<std::uint8_t> kCheck = {'1', '2', '3', '4', '5', '6', '7', '8', '9'};

TEST(Crc8SaeJ1850, CatalogCheckValue) {
    EXPECT_EQ(crc8SaeJ1850(kCheck.data(), kCheck.size(), 0x00, true), 0x4B);
}

TEST(Crc16Ccitt, CatalogCheckValue) {
    EXPECT_EQ(crc16Ccitt(kCheck.data(), kCheck.size(), 0x0000, true), 0x29B1);
}

// Empty first call returns the initial value with the final XOR applied: CRC-8 is
// 0xFF ^ 0xFF = 0x00; CRC-16 is 0xFFFF with no final XOR. Also exercises the
// null-at-zero-length contract.
TEST(Crc8SaeJ1850, EmptyInput) {
    EXPECT_EQ(crc8SaeJ1850(nullptr, 0, 0x00, true), 0x00);
}

TEST(Crc16Ccitt, EmptyInput) {
    EXPECT_EQ(crc16Ccitt(nullptr, 0, 0x0000, true), 0xFFFF);
}

// A two-segment CRC resumed across calls equals a single pass over the
// concatenation — the property the E2E profiles rely on (Data ID then data).
TEST(Crc16Ccitt, ChainedEqualsContiguous) {
    const std::vector<std::uint8_t> whole = {'1', '2', '3', '4', '5', '6', '7', '8', '9'};
    const std::uint16_t one = crc16Ccitt(whole.data(), whole.size(), 0x0000, true);
    const std::uint16_t part = crc16Ccitt(whole.data(), 4, 0x0000, true);
    const std::uint16_t two = crc16Ccitt(whole.data() + 4, whole.size() - 4, part, false);
    EXPECT_EQ(two, one);
}

// CRC-8 resume is the subtler case (it re-applies the final XOR on resume) and is
// the exact path E2E Profile 11 uses — so it gets its own chaining test.
TEST(Crc8SaeJ1850, ChainedEqualsContiguous) {
    const std::vector<std::uint8_t> whole = {'1', '2', '3', '4', '5', '6', '7', '8', '9'};
    const std::uint8_t one = crc8SaeJ1850(whole.data(), whole.size(), 0x00, true);
    const std::uint8_t part = crc8SaeJ1850(whole.data(), 4, 0x00, true);
    const std::uint8_t two = crc8SaeJ1850(whole.data() + 4, whole.size() - 4, part, false);
    EXPECT_EQ(two, one);
}

// start_value is ignored on the first call (AUTOSAR Crc_CalculateCRCx contract):
// is_first_call always starts from the algorithm's initial value.
TEST(Crc8SaeJ1850, StartValueIgnoredOnFirstCall) {
    const std::vector<std::uint8_t> d = {0x12, 0x34, 0x56};
    EXPECT_EQ(crc8SaeJ1850(d.data(), d.size(), 0xAB, true),
              crc8SaeJ1850(d.data(), d.size(), 0x00, true));
}

}  // namespace
}  // namespace tc8::crc
