// dispatchTcpFrame (sce_integration/tcp_pilot_common.h) over a machine that declares the
// `tcp_observed` event and over one that does not. A case that moves only on events of
// its own (a connect outcome, a timer) has no `Tcp_observed`; the shared TCP trait base
// must still compile for it, and must not pretend the event exists.

#include <variant>

#include <gtest/gtest.h>

#include "sce_integration/tcp_captured.h"
#include "sce_integration/tcp_pilot_common.h"
#include "tc8/captured_event.h"

namespace {

enum class EventWithObserved { Tcp_observed, Other };
enum class EventWithoutObserved { Other };

// The surface dispatchTcpFrame reads of a generated machine, and nothing more.
template <typename EventT>
struct StubMachine {
    struct PolicyType {
        using Event = EventT;
    };
    using CapturedType = ::tc8::TcpCaptured;

    int getCurrentState() const { return state_; }
    void raiseExternal(EventT) { ++raised_; }
    void step() { ++stepped_; }

    int state_ = 0;
    int raised_ = 0;
    int stepped_ = 0;
};

::tc8::CapturedEvent aTcpFrame() {
    ::tc8::TcpFrame f{};
    f.src_port = 4242;
    f.flags = 0x04;  // RST
    return f;
}

TEST(DispatchTcpFrame, RaisesTheEventAMachineDeclares) {
    StubMachine<EventWithObserved> sm;
    ::tc8::TcpCaptured c{};
    ::tc8::sce::tcp::dispatchTcpFrame(c, sm, aTcpFrame());
    EXPECT_EQ(sm.raised_, 1);
    EXPECT_EQ(sm.stepped_, 1);
    EXPECT_EQ(c.src_port, 4242);
}

TEST(DispatchTcpFrame, ADeclaredNothingMachineStillCompilesAndMirrorsTheFrame) {
    StubMachine<EventWithoutObserved> sm;
    ::tc8::TcpCaptured c{};
    ::tc8::sce::tcp::dispatchTcpFrame(c, sm, aTcpFrame());
    EXPECT_EQ(sm.raised_, 0);
    EXPECT_EQ(c.src_port, 4242);
}

TEST(DispatchTcpFrame, AFrameThatIsNotTcpIsIgnored) {
    StubMachine<EventWithObserved> sm;
    ::tc8::TcpCaptured c{};
    ::tc8::sce::tcp::dispatchTcpFrame(c, sm, ::tc8::CapturedEvent{});
    EXPECT_EQ(sm.raised_, 0);
    EXPECT_EQ(sm.stepped_, 0);
}

}  // namespace
