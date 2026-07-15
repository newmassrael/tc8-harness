#include <cstdint>
#include <stdexcept>
#include <vector>

#include <gtest/gtest.h>

#include "tc8/autosar/pn_filter.h"

namespace tc8::pn {
namespace {

// All values are synthetic: a 2-byte PNC bit vector at byte offset 2, and an ECU
// membership mask with bits 1 and 3 of byte 0 set (no real OEM cluster IDs).
PnFilter makeFilter() { return PnFilter(PnConfig{2, 2}); }

bool run(const std::vector<std::uint8_t>& pdu, const std::vector<std::uint8_t>& mask) {
    return makeFilter().relevant(pdu.data(), pdu.size(), mask);
}

// A set bit shared between the received range and the ECU mask -> relevant.
TEST(PnFilter, RequestsAMemberCluster) {
    EXPECT_TRUE(run({0x00, 0x00, 0x02, 0x00}, {0x0A, 0x00}));  // 0x02 & 0x0A = 0x02
}

// The received range requests only clusters the ECU does not belong to.
TEST(PnFilter, NoSharedClusterIsIrrelevant) {
    EXPECT_FALSE(run({0x00, 0x00, 0x04, 0x00}, {0x0A, 0x00}));  // 0x04 & 0x0A = 0
}

// An empty PN range (no cluster requested) is never relevant.
TEST(PnFilter, EmptyRangeIsIrrelevant) {
    EXPECT_FALSE(run({0x00, 0x00, 0x00, 0x00}, {0xFF, 0xFF}));
}

// A bit set only in the second byte of the range still matches.
TEST(PnFilter, MatchesInSecondRangeByte) {
    EXPECT_TRUE(run({0x00, 0x00, 0x00, 0x80}, {0x00, 0x80}));
}

// Bytes before pni_offset never contribute to relevance.
TEST(PnFilter, IgnoresBytesBeforeOffset) {
    EXPECT_FALSE(run({0xFF, 0xFF, 0x00, 0x00}, {0x01, 0x00}));
}

// A PDU too short to hold the configured range has no PN info -> irrelevant.
TEST(PnFilter, ShortPduHasNoRange) {
    const std::vector<std::uint8_t> pdu{0x00, 0x00, 0x02};  // needs offset 2 + len 2 = 4
    EXPECT_FALSE(makeFilter().relevant(pdu.data(), pdu.size(), {0x0A, 0x00}));
}

// The cluster mask must match the configured PN range width.
TEST(PnFilter, RejectsMaskOfWrongWidth) {
    const std::vector<std::uint8_t> pdu{0x00, 0x00, 0x02, 0x00};
    PnFilter f = makeFilter();
    EXPECT_THROW(f.relevant(pdu.data(), pdu.size(), {0x0A}), std::invalid_argument);
    EXPECT_THROW(f.relevant(pdu.data(), pdu.size(), {0x0A, 0x00, 0x00}),
                 std::invalid_argument);
}

// A zero-width PN range is a configuration error.
TEST(PnFilter, RejectsZeroLengthRange) {
    EXPECT_THROW(PnFilter(PnConfig{0, 0}), std::invalid_argument);
}

}  // namespace
}  // namespace tc8::pn
