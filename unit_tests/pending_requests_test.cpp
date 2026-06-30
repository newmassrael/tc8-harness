#include "pending_requests.h"

#include <vector>

#include <gtest/gtest.h>

namespace tc8::dut {
namespace {

// Records the order Requests were sent so the availability-gating policy can be
// asserted deterministically — no vsomeip, no threads. The Request type is a
// plain int payload standing in for the shared_ptr<vsomeip::message> production
// uses.
class Recorder {
public:
    PendingRequests<int> make() {
        return PendingRequests<int>([this](const int& r) { sent.push_back(r); });
    }
    std::vector<int> sent;
};

TEST(PendingRequests, SendsImmediatelyWhenAvailable) {
    Recorder rec;
    auto pending = rec.make();
    pending.submit(0x1234, 0x0001, /*available=*/true, 42);
    EXPECT_EQ(rec.sent, (std::vector<int>{42}));
}

TEST(PendingRequests, ParksWhenUnavailableUntilFlush) {
    Recorder rec;
    auto pending = rec.make();
    pending.submit(0x1234, 0x0001, /*available=*/false, 7);
    EXPECT_TRUE(rec.sent.empty());  // held, not dropped, not sent
    pending.flush(0x1234, 0x0001);
    EXPECT_EQ(rec.sent, (std::vector<int>{7}));
}

TEST(PendingRequests, FlushesParkedInSubmissionOrder) {
    Recorder rec;
    auto pending = rec.make();
    pending.submit(0x1234, 0x0001, false, 1);
    pending.submit(0x1234, 0x0001, false, 2);
    pending.submit(0x1234, 0x0001, false, 3);
    pending.flush(0x1234, 0x0001);
    EXPECT_EQ(rec.sent, (std::vector<int>{1, 2, 3}));
}

TEST(PendingRequests, FlushWithNothingParkedIsNoOp) {
    Recorder rec;
    auto pending = rec.make();
    pending.flush(0x1234, 0x0001);  // never submitted for this key
    EXPECT_TRUE(rec.sent.empty());
}

TEST(PendingRequests, FlushDrainsSoLaterFlushReplaysNothing) {
    Recorder rec;
    auto pending = rec.make();
    pending.submit(0x1234, 0x0001, false, 5);
    pending.flush(0x1234, 0x0001);
    pending.flush(0x1234, 0x0001);  // already drained — must not double-send
    EXPECT_EQ(rec.sent, (std::vector<int>{5}));
}

TEST(PendingRequests, KeysAreIndependent) {
    Recorder rec;
    auto pending = rec.make();
    pending.submit(0x1111, 0x0001, false, 10);
    pending.submit(0x2222, 0x0002, false, 20);
    pending.flush(0x1111, 0x0001);
    EXPECT_EQ(rec.sent, (std::vector<int>{10}));  // only key A flushed
    pending.flush(0x2222, 0x0002);
    EXPECT_EQ(rec.sent, (std::vector<int>{10, 20}));
}

TEST(PendingRequests, GateIsPerSubmitNotGlobal) {
    // An available submit sends immediately even while another key holds a parked
    // Request — the availability gate is evaluated per submit, not globally.
    Recorder rec;
    auto pending = rec.make();
    pending.submit(0x1111, 0x0001, false, 1);  // parked
    pending.submit(0x2222, 0x0002, true, 2);   // sent now
    EXPECT_EQ(rec.sent, (std::vector<int>{2}));
    pending.flush(0x1111, 0x0001);
    EXPECT_EQ(rec.sent, (std::vector<int>{2, 1}));
}

}  // namespace
}  // namespace tc8::dut
