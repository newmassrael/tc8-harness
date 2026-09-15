#include <cstdint>
#include <vector>

#include <gtest/gtest.h>

#include "tc8/net/socket_backend.h"
#include "tc8/testability_protocol.h"
#include "utm_module_adapter.h"

namespace tc8::scxml_module {
namespace {

// Issue one primitive and return the Result ID the module answers. The module
// owns no data plane, so `dat`, `peer` and the response buffer stay empty and
// the RID is the whole observable.
std::uint8_t ping(UtmModule &m, std::uint8_t pid = UtmModule::kPidPing) {
    tc8::testability::Header req;
    req.method_id = static_cast<std::uint16_t>((UtmModule::kGroup << 8) | pid);
    std::uint8_t rid = tc8::testability::kRidEOk;
    std::vector<std::uint8_t> resp;
    const tc8::net::Endpoint peer{};
    m.onPrimitive(req, nullptr, 0, peer, rid, resp);
    return rid;
}

TEST(ScxmlModule, OwnsExactlyItsGroup) {
    const UtmModule m;
    EXPECT_EQ(m.groups(), std::vector<std::uint8_t>{UtmModule::kGroup});
}

// The sequencing rule the SCXML exists to hold: a primitive outside the test
// boundary is refused, and nothing in the adapter enforces that.
TEST(ScxmlModule, RefusesPrimitiveBeforeStartTest) {
    UtmModule m;
    EXPECT_EQ(ping(m), tc8::testability::kRidENtf);
}

TEST(ScxmlModule, AnswersPrimitiveAfterStartTest) {
    UtmModule m;
    m.onStartTest();
    EXPECT_EQ(ping(m), tc8::testability::kRidEOk);
}

// END_TEST returns the module to its inactive state (PRS_TPSP §6.10.1) without
// unregistering it, so a later primitive is refused again rather than crashing.
TEST(ScxmlModule, RefusesPrimitiveAfterEndTest) {
    UtmModule m;
    m.onStartTest();
    ASSERT_EQ(ping(m), tc8::testability::kRidEOk);
    m.onEndTest();
    EXPECT_EQ(ping(m), tc8::testability::kRidENtf);
}

// The machine is total: repeating the accepted primitive stays accepted rather
// than falling off a one-shot edge.
TEST(ScxmlModule, RepeatedPrimitiveStaysAccepted) {
    UtmModule m;
    m.onStartTest();
    EXPECT_EQ(ping(m), tc8::testability::kRidEOk);
    EXPECT_EQ(ping(m), tc8::testability::kRidEOk);
    EXPECT_EQ(ping(m), tc8::testability::kRidEOk);
}

// A second START_TEST re-arms rather than being ignored, so a test system that
// restarts a trace does not have to unregister the module first.
TEST(ScxmlModule, StartTestReArmsFromAnyState) {
    UtmModule m;
    ASSERT_EQ(ping(m), tc8::testability::kRidENtf);
    m.onStartTest();
    EXPECT_EQ(ping(m), tc8::testability::kRidEOk);
    m.onStartTest();
    EXPECT_EQ(ping(m), tc8::testability::kRidEOk);
}

// An unknown PID under the owned GID is the adapter's own answer, not the
// machine's: the SCXML has no event for a primitive it was never told about.
TEST(ScxmlModule, UnknownPrimitiveIsNotFound) {
    UtmModule m;
    m.onStartTest();
    EXPECT_EQ(ping(m, 0x42), tc8::testability::kRidENtf);
    // The refusal must not have disturbed the sequencing state.
    EXPECT_EQ(ping(m), tc8::testability::kRidEOk);
}

}  // namespace
}  // namespace tc8::scxml_module
