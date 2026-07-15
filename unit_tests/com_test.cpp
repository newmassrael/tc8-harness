#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "tc8/autosar/com.h"
#include "hex.h"

namespace tc8::com {
namespace {

using tc8::test::toHex;

PduDef onePdu(SignalDef sig, std::size_t length) { return PduDef{1, length, {sig}}; }

// Little endian places bits LSb-first, linearly. A 10-bit all-ones signal at
// start bit 2 fills bits 2..11 -> byte0 0xFC, byte1 0x0F (the CAN/Intel layout).
TEST(ComLittleEndian, SpansByteBoundary) {
    SignalEngine eng{{onePdu(SignalDef{10, 2, 10, Endianness::kLittle}, 2)}};
    eng.setSignal(10, 0x3FF);
    EXPECT_EQ(toHex(eng.packPdu(1)), "fc0f");
}

// A non-symmetric value pins the bit order, not just the occupied span.
TEST(ComLittleEndian, NibbleHighInByte) {
    SignalEngine eng{{onePdu(SignalDef{10, 4, 4, Endianness::kLittle}, 1)}};
    eng.setSignal(10, 0xA);
    EXPECT_EQ(toHex(eng.packPdu(1)), "a0");
}

// Big endian (Motorola) sawtooth: start bit 1 is the MSb; the 4-bit value 0xB
// runs MSb-first into network bits 6..9, crossing the byte boundary to
// byte0 0x02, byte1 0xC0 (hand-derived from the cantools sawtooth formula).
TEST(ComBigEndian, SawtoothCrossesByteBoundary) {
    SignalEngine eng{{onePdu(SignalDef{20, 1, 4, Endianness::kBig}, 2)}};
    eng.setSignal(20, 0xB);
    EXPECT_EQ(toHex(eng.packPdu(1)), "02c0");
}

// Byte-aligned big endian: sawtooth start 7 is byte 0's MSb, so a whole byte
// lands as itself.
TEST(ComBigEndian, ByteAlignedIsIdentity) {
    SignalEngine eng{{onePdu(SignalDef{20, 7, 8, Endianness::kBig}, 1)}};
    eng.setSignal(20, 0xA5);
    EXPECT_EQ(toHex(eng.packPdu(1)), "a5");
}

// pack -> unpack round-trips the value for both byte orders, including a value
// that exceeds the signal width (masked to bit_size).
TEST(ComRoundTrip, LittleAndBigPreserveValue) {
    SignalEngine eng{{PduDef{2, 4,
                             {SignalDef{100, 3, 12, Endianness::kLittle},
                              SignalDef{101, 23, 9, Endianness::kBig}}}}};
    eng.setSignal(100, 0xABC);
    eng.setSignal(101, 0x1FF);
    const std::vector<std::uint8_t> buf = eng.packPdu(2);
    eng.unpackInto(2, buf.data(), buf.size());
    EXPECT_EQ(eng.lastReceived(100), std::optional<std::uint64_t>{0xABC});
    EXPECT_EQ(eng.lastReceived(101), std::optional<std::uint64_t>{0x1FF});
}

TEST(ComMasking, ValueWiderThanSignalIsTruncated) {
    SignalEngine eng{{onePdu(SignalDef{10, 0, 4, Endianness::kLittle}, 1)}};
    eng.setSignal(10, 0xFF);  // only the low 4 bits fit
    EXPECT_EQ(toHex(eng.packPdu(1)), "0f");
}

TEST(ComConfig, RejectsSignalBeyondPdu) {
    EXPECT_THROW(SignalEngine{{onePdu(SignalDef{10, 4, 8, Endianness::kLittle}, 1)}},
                 std::invalid_argument);
}

TEST(ComConfig, RejectsBadBitSize) {
    EXPECT_THROW(SignalEngine{{onePdu(SignalDef{10, 0, 0, Endianness::kLittle}, 1)}},
                 std::invalid_argument);
    EXPECT_THROW(SignalEngine{{onePdu(SignalDef{10, 0, 65, Endianness::kLittle}, 16)}},
                 std::invalid_argument);
}

TEST(ComConfig, RejectsDuplicateSignalId) {
    PduDef pdu{1, 2,
               {SignalDef{5, 0, 4, Endianness::kLittle}, SignalDef{5, 8, 4, Endianness::kLittle}}};
    EXPECT_THROW(SignalEngine{{pdu}}, std::invalid_argument);
}

TEST(ComLookup, UnknownSignalAndPduThrow) {
    SignalEngine eng{{onePdu(SignalDef{10, 0, 4, Endianness::kLittle}, 1)}};
    EXPECT_THROW(eng.setSignal(999, 0), std::invalid_argument);
    EXPECT_THROW(eng.packPdu(999), std::invalid_argument);
    EXPECT_EQ(eng.lastReceived(10), std::nullopt);
}

// hasSignal answers membership without throwing — the non-throwing complement of
// setSignal's unknown-id throw, so a caller can validate before acting.
TEST(ComLookup, HasSignalReportsMembership) {
    SignalEngine eng{{onePdu(SignalDef{10, 0, 4, Endianness::kLittle}, 1)}};
    EXPECT_TRUE(eng.hasSignal(10));
    EXPECT_FALSE(eng.hasSignal(999));
}

// The introspection accessors expose the injected database (signal width, PDU
// membership, PDU length) without copying it — the SSOT a module frames its
// responses from instead of duplicating the database.
TEST(ComIntrospection, ReportsWidthMembersAndLength) {
    // Two signals in one 3-byte PDU: a 10-bit (-> 2 bytes) and a 4-bit (-> 1 byte).
    SignalEngine eng{{PduDef{7, 3, {SignalDef{10, 0, 10, Endianness::kLittle},
                                    SignalDef{11, 12, 4, Endianness::kLittle}}}}};

    EXPECT_EQ(eng.signalWidth(10), 2u);  // ceil(10 / 8)
    EXPECT_EQ(eng.signalWidth(11), 1u);  // ceil(4 / 8)
    EXPECT_EQ(eng.pduLength(7), 3u);
    EXPECT_EQ(eng.pduSignals(7), (std::vector<std::uint32_t>{10, 11}));  // definition order
}

// Unknown ids answer 0 / empty rather than throwing, matching hasSignal's
// non-throwing contract (a caller can probe without catching).
TEST(ComIntrospection, UnknownIdsAreZeroAndEmpty) {
    SignalEngine eng{{onePdu(SignalDef{10, 0, 4, Endianness::kLittle}, 1)}};
    EXPECT_EQ(eng.signalWidth(999), 0u);
    EXPECT_EQ(eng.pduLength(999), 0u);
    EXPECT_TRUE(eng.pduSignals(999).empty());
}

}  // namespace
}  // namespace tc8::com
