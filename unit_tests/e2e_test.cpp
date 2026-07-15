#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "tc8/autosar/e2e.h"
#include "hex.h"

namespace tc8::e2e {
namespace {

using tc8::test::toHex;

// Worked vectors are the AUTOSAR FO PRS E2EProtocol Profile 5 examples (Data ID
// 0x1234), as published in the spec and reproduced by independent E2E libraries.
// protect() always advances the counter (AUTOSAR semantics), so the first
// protect reproduces the counter==1 example; the counter==0 example is verified
// through check(), which together pin the CRC for both counter values.
constexpr std::uint16_t kDataId = 0x1234;

// First protect of an all-zero PDU -> counter 1, CRC 0x8dcf written little-endian.
TEST(E2eP05Protect, FirstProtectMatchesCounter1Vector) {
    std::vector<std::uint8_t> pdu(8, 0x00);
    Profile05Protector p{Profile05Config{kDataId, 0, 1}};
    p.protect(pdu.data(), pdu.size());
    EXPECT_EQ(toHex(pdu), "cf8d010000000000");
}

// Same, with the header at offset 8 (the SOME/IP layout in the examples).
TEST(E2eP05Protect, Offset8FirstProtectVector) {
    std::vector<std::uint8_t> pdu(16, 0x00);
    Profile05Protector p{Profile05Config{kDataId, 8, 1}};
    p.protect(pdu.data(), pdu.size());
    EXPECT_EQ(toHex(pdu), "0000000000000000fbd6010000000000");
}

// The counter==0 example (CRC 0xca1c) must verify clean on first reception.
TEST(E2eP05Check, AcceptsCounter0Vector) {
    const std::vector<std::uint8_t> pdu{0x1c, 0xca, 0x00, 0, 0, 0, 0, 0};
    Profile05Checker c{Profile05Config{kDataId, 0, 1}};
    EXPECT_EQ(c.check(pdu.data(), pdu.size()), CheckStatus::kOk);
}

TEST(E2eP05Check, AcceptsOffset8Counter0Vector) {
    const std::vector<std::uint8_t> pdu{0, 0, 0, 0, 0, 0, 0, 0, 0x28, 0x91, 0x00, 0, 0, 0, 0, 0};
    Profile05Checker c{Profile05Config{kDataId, 8, 1}};
    EXPECT_EQ(c.check(pdu.data(), pdu.size()), CheckStatus::kOk);
}

// A counter byte tampered to 0x01 no longer matches the CRC computed for 0x00.
TEST(E2eP05Check, RejectsCorruptedFrame) {
    const std::vector<std::uint8_t> pdu{0x1c, 0xca, 0x01, 0, 0, 0, 0, 0};
    Profile05Checker c{Profile05Config{kDataId, 0, 1}};
    EXPECT_EQ(c.check(pdu.data(), pdu.size()), CheckStatus::kError);
}

// protect -> check round-trip across consecutive counters.
TEST(E2eP05RoundTrip, ConsecutiveCountersAreOk) {
    Profile05Protector p{Profile05Config{kDataId, 0, 1}};
    Profile05Checker c{Profile05Config{kDataId, 0, 1}};
    std::vector<std::uint8_t> pdu(8, 0x00);
    p.protect(pdu.data(), pdu.size());
    EXPECT_EQ(c.check(pdu.data(), pdu.size()), CheckStatus::kOk);
    p.protect(pdu.data(), pdu.size());
    EXPECT_EQ(c.check(pdu.data(), pdu.size()), CheckStatus::kOk);
}

// Re-presenting the same frame is a duplicate, not a fresh message.
TEST(E2eP05RoundTrip, RepeatedCounterIsRepeated) {
    Profile05Protector p{Profile05Config{kDataId, 0, 1}};
    Profile05Checker c{Profile05Config{kDataId, 0, 1}};
    std::vector<std::uint8_t> pdu(8, 0x00);
    p.protect(pdu.data(), pdu.size());
    EXPECT_EQ(c.check(pdu.data(), pdu.size()), CheckStatus::kOk);
    EXPECT_EQ(c.check(pdu.data(), pdu.size()), CheckStatus::kRepeated);
}

// A counter jump past max_delta_counter is flagged as a wrong sequence.
TEST(E2eP05RoundTrip, CounterJumpBeyondMaxIsWrongSequence) {
    Profile05Protector p{Profile05Config{kDataId, 0, 1}};
    Profile05Checker c{Profile05Config{kDataId, 0, 1}};  // max_delta_counter = 1
    std::vector<std::uint8_t> pdu(8, 0x00);
    p.protect(pdu.data(), pdu.size());                          // counter 1
    EXPECT_EQ(c.check(pdu.data(), pdu.size()), CheckStatus::kOk);
    p.protect(pdu.data(), pdu.size());                          // counter 2 (dropped)
    p.protect(pdu.data(), pdu.size());                          // counter 3
    EXPECT_EQ(c.check(pdu.data(), pdu.size()), CheckStatus::kWrongSequence);
}

TEST(E2eP05, RejectsPduShorterThanHeader) {
    std::vector<std::uint8_t> pdu(2, 0x00);
    Profile05Protector p{Profile05Config{kDataId, 0, 1}};
    EXPECT_THROW(p.protect(pdu.data(), pdu.size()), std::invalid_argument);
}

// AUTOSAR FO PRS E2EProtocol Profile 11 (Data ID 0x123). The CRC is CRC-8/SAE-J1850
// (polynomial 0x1D) but with start value AND XOR value 0x00 (PRS_E2E_00070; Profile
// 11 is bus-compatible to Profile 1) — i.e. Crc_CalculateCRC8 seeded with the
// complement 0xFF. The expected bytes below were independently recomputed from that
// rule (cc/91 BOTH, 2a/77 NIBBLE), so they are spec-anchored, not round-trip-only.
// As with P05, first protect reproduces the counter==1 case; check() pins counter==0.
constexpr std::uint16_t kP11DataId = 0x123;

TEST(E2eP11Protect, BothModeFirstProtectVector) {
    std::vector<std::uint8_t> pdu(8, 0x00);
    Profile11Protector p{Profile11Config{kP11DataId, DataIdMode::kBoth, 0, 1}};
    p.protect(pdu.data(), pdu.size());
    EXPECT_EQ(toHex(pdu), "9101000000000000");
}

TEST(E2eP11Protect, NibbleModeFirstProtectVector) {
    std::vector<std::uint8_t> pdu(8, 0x00);
    Profile11Protector p{Profile11Config{kP11DataId, DataIdMode::kNibble, 0, 1}};
    p.protect(pdu.data(), pdu.size());
    EXPECT_EQ(toHex(pdu), "7711000000000000");
}

TEST(E2eP11Protect, NibbleModeOffset8Vector) {
    std::vector<std::uint8_t> pdu(16, 0x00);
    Profile11Protector p{Profile11Config{kP11DataId, DataIdMode::kNibble, 8, 1}};
    p.protect(pdu.data(), pdu.size());
    EXPECT_EQ(toHex(pdu), "00000000000000002011000000000000");
}

TEST(E2eP11Check, BothModeAcceptsCounter0Vector) {
    const std::vector<std::uint8_t> pdu{0xcc, 0x00, 0, 0, 0, 0, 0, 0};
    Profile11Checker c{Profile11Config{kP11DataId, DataIdMode::kBoth, 0, 1}};
    EXPECT_EQ(c.check(pdu.data(), pdu.size()), CheckStatus::kOk);
}

TEST(E2eP11Check, BothModeRejectsCorruptedFrame) {
    const std::vector<std::uint8_t> pdu{0xcc, 0x10, 0, 0, 0, 0, 0, 0};
    Profile11Checker c{Profile11Config{kP11DataId, DataIdMode::kBoth, 0, 1}};
    EXPECT_EQ(c.check(pdu.data(), pdu.size()), CheckStatus::kError);
}

TEST(E2eP11Check, NibbleModeAcceptsCounter0Vector) {
    const std::vector<std::uint8_t> pdu{0x2a, 0x10, 0, 0, 0, 0, 0, 0};
    Profile11Checker c{Profile11Config{kP11DataId, DataIdMode::kNibble, 0, 1}};
    EXPECT_EQ(c.check(pdu.data(), pdu.size()), CheckStatus::kOk);
}

TEST(E2eP11Check, NibbleModeOffset8AcceptsVector) {
    const std::vector<std::uint8_t> pdu{0, 0, 0, 0, 0, 0, 0, 0, 0x7d, 0x10, 0, 0, 0, 0, 0, 0};
    Profile11Checker c{Profile11Config{kP11DataId, DataIdMode::kNibble, 8, 1}};
    EXPECT_EQ(c.check(pdu.data(), pdu.size()), CheckStatus::kOk);
}

TEST(E2eP11RoundTrip, ConsecutiveCountersAreOk) {
    Profile11Protector p{Profile11Config{kP11DataId, DataIdMode::kNibble, 0, 1}};
    Profile11Checker c{Profile11Config{kP11DataId, DataIdMode::kNibble, 0, 1}};
    std::vector<std::uint8_t> pdu(8, 0x00);
    p.protect(pdu.data(), pdu.size());
    EXPECT_EQ(c.check(pdu.data(), pdu.size()), CheckStatus::kOk);
    p.protect(pdu.data(), pdu.size());
    EXPECT_EQ(c.check(pdu.data(), pdu.size()), CheckStatus::kOk);
}

TEST(E2eP11, RejectsPduShorterThanHeader) {
    std::vector<std::uint8_t> pdu(1, 0x00);
    Profile11Protector p{Profile11Config{kP11DataId, DataIdMode::kBoth, 0, 1}};
    EXPECT_THROW(p.protect(pdu.data(), pdu.size()), std::invalid_argument);
}

// The P11 counter is 4-bit and wraps modulo 15 (max 0x0E, 0x0F reserved). The
// checker's delta must stay correct across the 14 -> 0 wrap.
TEST(E2eP11RoundTrip, CounterWrapsModulo15) {
    Profile11Protector p{Profile11Config{kP11DataId, DataIdMode::kBoth, 0, 1}};
    Profile11Checker c{Profile11Config{kP11DataId, DataIdMode::kBoth, 0, 1}};
    std::vector<std::uint8_t> pdu(8, 0x00);
    for (int i = 0; i < 14; ++i) {  // counters 1..14, each accepted
        p.protect(pdu.data(), pdu.size());
        ASSERT_EQ(c.check(pdu.data(), pdu.size()), CheckStatus::kOk);
    }
    p.protect(pdu.data(), pdu.size());          // counter (14 + 1) % 15 = 0
    EXPECT_EQ(pdu[1] & 0x0F, 0x00);             // low nibble holds the wrapped counter
    EXPECT_EQ(c.check(pdu.data(), pdu.size()), CheckStatus::kOk);  // delta 14->0 is 1
}

// A duplicate frame is Repeated; a jump past max_delta_counter is WrongSequence.
TEST(E2eP11RoundTrip, RepeatedAndWrongSequence) {
    Profile11Protector p{Profile11Config{kP11DataId, DataIdMode::kBoth, 0, 1}};
    Profile11Checker c{Profile11Config{kP11DataId, DataIdMode::kBoth, 0, 1}};
    std::vector<std::uint8_t> pdu(8, 0x00);
    p.protect(pdu.data(), pdu.size());
    EXPECT_EQ(c.check(pdu.data(), pdu.size()), CheckStatus::kOk);
    EXPECT_EQ(c.check(pdu.data(), pdu.size()), CheckStatus::kRepeated);
    p.protect(pdu.data(), pdu.size());  // counter 2 (dropped)
    p.protect(pdu.data(), pdu.size());  // counter 3
    EXPECT_EQ(c.check(pdu.data(), pdu.size()), CheckStatus::kWrongSequence);
}

}  // namespace
}  // namespace tc8::e2e
