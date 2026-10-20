#include "service_requests.h"

#include <cstdint>
#include <string>
#include <vector>

#include <gtest/gtest.h>

namespace tc8::dut {
namespace {

// A ServiceRequests over a recording stack: every request and release it makes is
// appended, in order, as a string, so a test pins the whole call SEQUENCE the stack would
// see (request_service / release_service), not just a count. No vsomeip, no threads.
class Recorder {
public:
    ServiceRequests make() {
        return ServiceRequests(
            [this](std::uint16_t s, std::uint16_t i, std::uint8_t major) {
                calls.push_back("request " + name(s, i) + " major=" + std::to_string(major));
            },
            [this](std::uint16_t s, std::uint16_t i) {
                calls.push_back("release " + name(s, i));
            });
    }
    std::vector<std::string> calls;

private:
    static std::string name(std::uint16_t s, std::uint16_t i) {
        return std::to_string(s) + "/" + std::to_string(i);
    }
};

using Calls = std::vector<std::string>;

TEST(ServiceRequests, ARepeatedRequestForAHeldPairReachesTheStackOnce) {
    Recorder r;
    auto reqs = r.make();
    reqs.request(10, 1, 3);
    reqs.request(10, 1, 3);
    reqs.request(10, 1, 7);  // the first request's major stands while the pair is held
    EXPECT_EQ(r.calls, (Calls{"request 10/1 major=3"}));
    EXPECT_TRUE(reqs.holds(10, 1));
}

// The reason release exists: after it, the next request is a real request again, which
// is what makes the stack start discovery from the beginning for the second activation.
TEST(ServiceRequests, ReleaseThenRequestRequestsTheStackTwice) {
    Recorder r;
    auto reqs = r.make();
    reqs.request(10, 1, 3);
    EXPECT_TRUE(reqs.release(10, 1));
    EXPECT_FALSE(reqs.holds(10, 1));
    reqs.request(10, 1, 9);  // a new hold: its own major
    EXPECT_EQ(r.calls, (Calls{"request 10/1 major=3", "release 10/1", "request 10/1 major=9"}));
    EXPECT_TRUE(reqs.holds(10, 1));
}

// A pair released by the owner is forgotten, so teardown does not release it again; a
// pair still held at teardown is released once.
TEST(ServiceRequests, TeardownReleasesWhatIsStillHeldAndNothingReleasedTwice) {
    Recorder r;
    auto reqs = r.make();
    reqs.request(10, 1, 3);
    reqs.request(20, 2, 3);
    reqs.release(10, 1);
    reqs.releaseAll();
    EXPECT_EQ(r.calls, (Calls{"request 10/1 major=3", "request 20/2 major=3", "release 10/1",
                              "release 20/2"}));

    // A pair released, requested again and released at teardown balances: one request,
    // one release, per hold.
    Recorder again;
    auto cycle = again.make();
    cycle.request(10, 1, 3);
    cycle.release(10, 1);
    cycle.request(10, 1, 3);
    cycle.releaseAll();
    EXPECT_EQ(again.calls, (Calls{"request 10/1 major=3", "release 10/1",
                                  "request 10/1 major=3", "release 10/1"}));
}

TEST(ServiceRequests, ReleasingAPairNothingRequestedTouchesNothing) {
    Recorder r;
    auto reqs = r.make();
    EXPECT_FALSE(reqs.release(10, 1));
    reqs.request(10, 1, 3);
    EXPECT_FALSE(reqs.release(10, 2));  // another instance of the same service
    EXPECT_FALSE(reqs.release(11, 1));  // another service
    EXPECT_EQ(r.calls, (Calls{"request 10/1 major=3"}));
    EXPECT_TRUE(reqs.release(10, 1));
    EXPECT_FALSE(reqs.release(10, 1));  // already let go of: not released a second time
    EXPECT_EQ(r.calls, (Calls{"request 10/1 major=3", "release 10/1"}));
}

TEST(ServiceRequests, PairsAreIndependent) {
    Recorder r;
    auto reqs = r.make();
    reqs.request(10, 1, 3);
    reqs.request(10, 2, 3);
    reqs.release(10, 1);
    EXPECT_FALSE(reqs.holds(10, 1));
    EXPECT_TRUE(reqs.holds(10, 2));
    reqs.request(10, 2, 3);  // still held: no second request for it
    EXPECT_EQ(r.calls, (Calls{"request 10/1 major=3", "request 10/2 major=3", "release 10/1"}));
}

}  // namespace
}  // namespace tc8::dut
