#include "pending_requests.h"

#include <cstdint>
#include <map>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

namespace tc8::dut {
namespace {

using Key = std::pair<std::uint16_t, std::uint16_t>;

// Drives PendingRequests with a controllable availability source and a recording
// sender — no vsomeip, no threads. The test flips `available` to simulate an
// ON_AVAILABLE edge; `sent` records send order. This exercises the actual GATE
// (the injected availability query deciding send-inline vs park) and the flush, not
// just a buffer fed a pre-computed bool. The Request type is a plain int payload
// standing in for the shared_ptr<vsomeip::message> production uses.
class Harness {
public:
    PendingRequests<int> make() {
        return PendingRequests<int>(
            [this](std::uint16_t s, std::uint16_t i) { return available[{s, i}]; },
            [this](const int& r) { sent.push_back(r); });
    }
    std::map<Key, bool> available;
    std::vector<int> sent;
};

TEST(PendingRequests, SendsInlineWhenAvailable) {
    Harness h;
    h.available[{0x1234, 1}] = true;
    auto p = h.make();
    p.submit(0x1234, 1, 42);
    EXPECT_EQ(h.sent, (std::vector<int>{42}));
}

TEST(PendingRequests, ParksWhenUnavailableThenFlushesOnAvailable) {
    Harness h;
    auto p = h.make();
    p.submit(0x1234, 1, 7);              // unavailable (default false) → park
    EXPECT_TRUE(h.sent.empty());         // held, not dropped, not sent
    h.available[{0x1234, 1}] = true;     // ON_AVAILABLE edge
    p.onAvailable(0x1234, 1);
    EXPECT_EQ(h.sent, (std::vector<int>{7}));
}

TEST(PendingRequests, GateIsQueriedPerSubmitNotCachedAtConstruction) {
    Harness h;
    auto p = h.make();
    p.submit(0x1234, 1, 1);              // unavailable → park
    h.available[{0x1234, 1}] = true;
    p.submit(0x1234, 1, 2);              // now available → inline, before the flush
    EXPECT_EQ(h.sent, (std::vector<int>{2}));
    p.onAvailable(0x1234, 1);            // flush the earlier parked one
    EXPECT_EQ(h.sent, (std::vector<int>{2, 1}));
}

TEST(PendingRequests, FlushesParkedInSubmissionOrder) {
    Harness h;
    auto p = h.make();
    p.submit(0x1234, 1, 1);
    p.submit(0x1234, 1, 2);
    p.submit(0x1234, 1, 3);
    h.available[{0x1234, 1}] = true;
    p.onAvailable(0x1234, 1);
    EXPECT_EQ(h.sent, (std::vector<int>{1, 2, 3}));
}

TEST(PendingRequests, OnAvailableWithNothingParkedIsNoOp) {
    Harness h;
    auto p = h.make();
    p.onAvailable(0x1234, 1);            // never submitted for this key
    EXPECT_TRUE(h.sent.empty());
}

TEST(PendingRequests, OnAvailableDrainsSoSecondReplaysNothing) {
    Harness h;
    auto p = h.make();
    p.submit(0x1234, 1, 5);
    p.onAvailable(0x1234, 1);
    p.onAvailable(0x1234, 1);            // already drained — must not double-send
    EXPECT_EQ(h.sent, (std::vector<int>{5}));
}

TEST(PendingRequests, KeysAreIndependent) {
    Harness h;
    auto p = h.make();
    p.submit(0x1111, 1, 10);
    p.submit(0x2222, 2, 20);
    p.onAvailable(0x1111, 1);
    EXPECT_EQ(h.sent, (std::vector<int>{10}));  // only key A flushed
    p.onAvailable(0x2222, 2);
    EXPECT_EQ(h.sent, (std::vector<int>{10, 20}));
}

}  // namespace
}  // namespace tc8::dut
