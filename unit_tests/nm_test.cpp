#include <chrono>
#include <cstdint>
#include <stdexcept>
#include <vector>

#include <gtest/gtest.h>

#include "autosar/nm.h"

namespace tc8::nm {
namespace {

using ms = std::chrono::milliseconds;

// Synthetic timing/layout (no OEM values): a short, distinct duration per timer
// so a single mainFunction() step crosses exactly one threshold.
Timing timing() { return Timing{ms{50}, ms{200}, ms{100}, ms{150}}; }
PduLayout layout() { return PduLayout{8, 0, 1, 2, 6}; }

StateMachine make() { return StateMachine(timing(), layout(), 0x42); }

// Bus Sleep + network request enters Network Mode at Repeat Message, sending one
// NM message on entry.
TEST(NmStateMachine, ActiveStartupEntersRepeatMessage) {
    StateMachine sm = make();
    int tx = 0;
    sm.onTransmit = [&](const std::vector<std::uint8_t>&) { ++tx; };
    EXPECT_EQ(sm.state(), State::kBusSleep);
    sm.requestNetwork();
    EXPECT_EQ(sm.state(), State::kRepeatMessage);
    EXPECT_EQ(tx, 1);
}

// A received NM PDU wakes a dormant node passively.
TEST(NmStateMachine, PassiveStartupOnRx) {
    StateMachine sm = make();
    const std::vector<std::uint8_t> pdu(8, 0x00);
    sm.rxNmPdu(pdu.data(), pdu.size());
    EXPECT_EQ(sm.state(), State::kRepeatMessage);
}

// Repeat Message timer expiry goes to Normal Operation when the network is
// requested, Ready Sleep when it is released.
TEST(NmStateMachine, RepeatMessageToNormalOperation) {
    StateMachine sm = make();
    sm.requestNetwork();
    sm.mainFunction(ms{100});  // repeat_message expires
    EXPECT_EQ(sm.state(), State::kNormalOperation);
}

TEST(NmStateMachine, RepeatMessageToReadySleepWhenReleased) {
    StateMachine sm = make();
    sm.requestNetwork();
    sm.releaseNetwork();        // still in Repeat Message, now not requested
    EXPECT_EQ(sm.state(), State::kRepeatMessage);
    sm.mainFunction(ms{100});
    EXPECT_EQ(sm.state(), State::kReadySleep);
}

// Normal Operation <-> Ready Sleep follows network release/request.
TEST(NmStateMachine, NormalOperationReadySleepToggle) {
    StateMachine sm = make();
    sm.requestNetwork();
    sm.mainFunction(ms{100});
    ASSERT_EQ(sm.state(), State::kNormalOperation);
    sm.releaseNetwork();
    EXPECT_EQ(sm.state(), State::kReadySleep);
    sm.requestNetwork();
    EXPECT_EQ(sm.state(), State::kNormalOperation);
}

// Ready Sleep -> Prepare Bus Sleep on NM-Timeout, then -> Bus Sleep on Wait Bus
// Sleep timer.
TEST(NmStateMachine, ReadySleepDownToBusSleep) {
    StateMachine sm = make();
    sm.requestNetwork();
    sm.mainFunction(ms{100});   // -> Normal Operation
    sm.releaseNetwork();        // -> Ready Sleep
    sm.mainFunction(ms{200});   // NM-Timeout expires
    EXPECT_EQ(sm.state(), State::kPrepareBusSleep);
    sm.mainFunction(ms{150});   // Wait Bus Sleep expires
    EXPECT_EQ(sm.state(), State::kBusSleep);
}

// A received NM PDU in Ready Sleep restarts the NM-Timeout, deferring sleep.
TEST(NmStateMachine, RxInReadySleepDefersSleep) {
    StateMachine sm = make();
    sm.requestNetwork();
    sm.mainFunction(ms{100});   // Normal Operation
    sm.releaseNetwork();        // Ready Sleep, NM-Timeout = 200
    sm.mainFunction(ms{150});   // 50 left
    ASSERT_EQ(sm.state(), State::kReadySleep);
    const std::vector<std::uint8_t> pdu(8, 0x00);
    sm.rxNmPdu(pdu.data(), pdu.size());  // restart NM-Timeout to 200
    sm.mainFunction(ms{150});   // still 50 left -> not asleep
    EXPECT_EQ(sm.state(), State::kReadySleep);
}

// Prepare Bus Sleep wakes back to Network Mode on a network request.
TEST(NmStateMachine, PrepareBusSleepWakesOnRequest) {
    StateMachine sm = make();
    sm.requestNetwork();
    sm.mainFunction(ms{100});
    sm.releaseNetwork();
    sm.mainFunction(ms{200});
    ASSERT_EQ(sm.state(), State::kPrepareBusSleep);
    sm.requestNetwork();
    EXPECT_EQ(sm.state(), State::kRepeatMessage);
}

// Normal Operation transmits one NM message per msg_cycle.
TEST(NmStateMachine, PeriodicTransmitInNormalOperation) {
    StateMachine sm = make();
    sm.requestNetwork();
    sm.mainFunction(ms{100});   // -> Normal Operation
    int tx = 0;
    sm.onTransmit = [&](const std::vector<std::uint8_t>&) { ++tx; };
    sm.mainFunction(ms{50});    // one msg_cycle
    EXPECT_EQ(tx, 1);
}

// buildPdu places the node id and user data at their configured offsets.
TEST(NmStateMachine, BuildPduLaysOutFields) {
    StateMachine sm = make();
    const std::vector<std::uint8_t> ud = {0xDE, 0xAD, 0xBE, 0xEF};
    sm.setUserData(ud.data(), ud.size());
    const std::vector<std::uint8_t> pdu = sm.buildPdu();
    ASSERT_EQ(pdu.size(), 8u);
    EXPECT_EQ(pdu[0], 0x42);                       // source node id
    EXPECT_EQ(pdu[1], 0x00);                       // control bit vector
    EXPECT_EQ(pdu[2], 0xDE);                       // user data start
    EXPECT_EQ(pdu[5], 0xEF);
}

// onTransition reports each state change.
TEST(NmStateMachine, TransitionCallbackFires) {
    StateMachine sm = make();
    std::vector<State> seen;
    sm.onTransition = [&](State, State to) { seen.push_back(to); };
    sm.requestNetwork();        // -> Repeat Message
    sm.mainFunction(ms{100});   // -> Normal Operation
    ASSERT_EQ(seen.size(), 2u);
    EXPECT_EQ(seen[0], State::kRepeatMessage);
    EXPECT_EQ(seen[1], State::kNormalOperation);
}

TEST(NmStateMachine, RejectsLayoutBeyondPdu) {
    EXPECT_THROW(StateMachine(timing(), PduLayout{4, 0, 1, 2, 6}, 0x00), std::invalid_argument);
}

// Repeat Message State also transmits cyclically (not just Normal Operation):
// one message on entry, then one per msg_cycle.
TEST(NmStateMachine, PeriodicTransmitInRepeatMessage) {
    StateMachine sm = make();
    int tx = 0;
    sm.onTransmit = [&](const std::vector<std::uint8_t>&) { ++tx; };
    sm.requestNetwork();        // -> Repeat Message, transmits on entry
    EXPECT_EQ(tx, 1);
    sm.mainFunction(ms{50});    // one msg_cycle, still in Repeat Message
    EXPECT_EQ(tx, 2);
}

// A received NM PDU wakes the node out of Prepare Bus Sleep, passively.
TEST(NmStateMachine, PrepareBusSleepWakesOnRx) {
    StateMachine sm = make();
    sm.requestNetwork();
    sm.mainFunction(ms{100});   // -> Normal Operation
    sm.releaseNetwork();        // -> Ready Sleep
    sm.mainFunction(ms{200});   // NM-Timeout -> Prepare Bus Sleep
    ASSERT_EQ(sm.state(), State::kPrepareBusSleep);
    const std::vector<std::uint8_t> pdu(8, 0x00);
    sm.rxNmPdu(pdu.data(), pdu.size());
    EXPECT_EQ(sm.state(), State::kRepeatMessage);
}

// ── Node detection (Repeat Message Request, SWS Nm CBV bit 0) ──

// A local repeat-message request re-enters Repeat Message from Normal Operation
// and sets the Repeat Message Request bit in the transmitted PDU's CBV (offset 1).
TEST(NmStateMachine, RepeatMessageRequestReentersAndSetsBit) {
    StateMachine sm = make();
    std::vector<std::uint8_t> last;
    sm.onTransmit = [&](const std::vector<std::uint8_t>& p) { last = p; };
    sm.requestNetwork();
    sm.mainFunction(ms{100});  // -> Normal Operation
    ASSERT_EQ(sm.state(), State::kNormalOperation);
    sm.requestRepeatMessage();
    EXPECT_EQ(sm.state(), State::kRepeatMessage);
    ASSERT_EQ(last.size(), 8u);
    EXPECT_NE(last[1] & kCbvRepeatMessageRequest, 0);  // RMR bit set on tx (CBV at off 1)
}

// A peer's PDU with the RMR bit set drives a receiver back into Repeat Message
// (node detection); the same PDU without the bit leaves it in Normal Operation.
TEST(NmStateMachine, RxRepeatMessageBitReentersRepeatMessage) {
    StateMachine sm = make();
    sm.requestNetwork();
    sm.mainFunction(ms{100});  // -> Normal Operation
    ASSERT_EQ(sm.state(), State::kNormalOperation);
    std::vector<std::uint8_t> pdu(8, 0x00);
    pdu[1] = kCbvRepeatMessageRequest;  // peer requests repeat (CBV at off 1)
    sm.rxNmPdu(pdu.data(), pdu.size());
    EXPECT_EQ(sm.state(), State::kRepeatMessage);
}

TEST(NmStateMachine, RxWithoutRepeatBitStaysInNormalOperation) {
    StateMachine sm = make();
    sm.requestNetwork();
    sm.mainFunction(ms{100});  // -> Normal Operation
    ASSERT_EQ(sm.state(), State::kNormalOperation);
    const std::vector<std::uint8_t> pdu(8, 0x00);  // CBV clear
    sm.rxNmPdu(pdu.data(), pdu.size());
    EXPECT_EQ(sm.state(), State::kNormalOperation);
}

// A receiver re-entering Repeat Message because of a peer's request must not set
// its own RMR bit (only the originator does), so the request cannot storm.
TEST(NmStateMachine, ReceiverReenteringDoesNotSetOwnBit) {
    StateMachine sm = make();
    std::vector<std::uint8_t> last;
    sm.onTransmit = [&](const std::vector<std::uint8_t>& p) { last = p; };
    sm.requestNetwork();
    sm.mainFunction(ms{100});  // -> Normal Operation
    std::vector<std::uint8_t> rmr(8, 0x00);
    rmr[1] = kCbvRepeatMessageRequest;
    sm.rxNmPdu(rmr.data(), rmr.size());  // re-enter via the peer request (tx on entry)
    ASSERT_EQ(sm.state(), State::kRepeatMessage);
    ASSERT_EQ(last.size(), 8u);
    EXPECT_EQ(last[1] & kCbvRepeatMessageRequest, 0);  // the receiver does not propagate
}

// Outside Network Mode there is nothing to repeat: the request is a no-op.
TEST(NmStateMachine, RepeatMessageRequestIgnoredInBusSleep) {
    StateMachine sm = make();
    sm.requestRepeatMessage();
    EXPECT_EQ(sm.state(), State::kBusSleep);
}

}  // namespace
}  // namespace tc8::nm
