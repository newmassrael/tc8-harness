#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <vector>

namespace tc8::nm {

// AUTOSAR Network Management states (SWS UDPNetworkManagement / CanNm). The
// canonical machine has five: Bus Sleep, Prepare Bus Sleep, and the Network Mode
// sub-states Repeat Message, Normal Operation, Ready Sleep. (The design sketch's
// "Network Startup" is not a standard Nm state and is intentionally omitted.)
enum class State {
    kBusSleep,
    kPrepareBusSleep,
    kRepeatMessage,
    kNormalOperation,
    kReadySleep,
};

// Timer durations (OEM config). msg_cycle drives periodic NM tx; msg_timeout is
// the NM-Timeout restarted on every tx/rx; repeat_message bounds Repeat Message
// State; wait_bus_sleep bounds Prepare Bus Sleep.
struct Timing {
    std::chrono::milliseconds msg_cycle;
    std::chrono::milliseconds msg_timeout;
    std::chrono::milliseconds repeat_message;
    std::chrono::milliseconds wait_bus_sleep;
};

// Control Bit Vector bits at their AUTOSAR-standard bus-NM (CanNm / UdpNm)
// positions.
//  * Repeat Message Request (bit 0): set by a node triggering node detection;
//    every receiver that sees it re-enters Repeat Message State so newly-joined
//    nodes are re-announced cluster-wide.
//  * Active Wakeup (bit 5): the node's wakeup REASON — set when this node itself
//    requested the network (Nm_NetworkRequest) during the current Network Mode
//    episode, and cleared on the return to Bus Sleep. It stays set for the rest of
//    that episode even after the request is released (a released node held awake
//    passively still carries the reason it woke), and is NEVER set on a purely
//    passive startup (woke on a received NM message). Lets a coordinator tell which
//    nodes' wakeups were active.
inline constexpr std::uint8_t kCbvRepeatMessageRequest = 0x01;
inline constexpr std::uint8_t kCbvActiveWakeup = 0x20;

// NM PDU field layout (OEM config). Offsets are byte offsets within a PDU of
// pdu_length bytes. control_bit_vector_off is the wire position of the Control
// Bit Vector. The machine models the standard Repeat Message Request and Active
// Wakeup bits within it — reading the former on rx and setting both on tx; the
// remaining CBV bits (sleep-ready, partial-network, ...) stay an OEM concern and
// are left zero.
struct PduLayout {
    std::size_t pdu_length;
    std::size_t source_node_id_off;
    std::size_t control_bit_vector_off;
    std::size_t user_data_off;
    std::size_t user_data_len;
};

// AUTOSAR NM state machine — the mechanism only; all durations/layout/node id are
// injected config. The machine is advanced by mainFunction() (the Nm_MainFunction
// analog, parameterized by elapsed time so it is deterministically testable with
// no real clock). It performs no I/O: rxNmPdu() is fed received PDUs by the owning
// module and onTransmit fires when the machine wants to send (the module owns the
// socket and timer that call these).
class StateMachine {
public:
    // Throws std::invalid_argument if the layout fields fall outside pdu_length.
    StateMachine(Timing timing, PduLayout layout, std::uint8_t node_id);

    void requestNetwork();   // ComM full-com: the network is needed
    void releaseNetwork();   // ComM no-com: the network is no longer needed
    void rxNmPdu(const std::uint8_t* pdu, std::size_t len);  // an NM PDU arrived

    // Trigger node detection (the Nm_RepeatMessageRequest analog): re-enter Repeat
    // Message State and set the Repeat Message Request bit in transmitted PDUs for
    // its duration, so the whole cluster re-enters Repeat Message and re-announces.
    // A no-op outside Network Mode (Bus Sleep / Prepare Bus Sleep have nothing to
    // repeat).
    void requestRepeatMessage();

    // Advance the machine by `elapsed`; call periodically with a period finer
    // than the configured timers (AUTOSAR Nm_MainFunction model).
    void mainFunction(std::chrono::milliseconds elapsed);

    // Application user data placed into transmitted PDUs (truncated/zero-padded
    // to user_data_len).
    void setUserData(const std::uint8_t* data, std::size_t len);

    State state() const { return state_; }

    // Assemble the current NM PDU per the layout: source node id, the modeled
    // Control Bit Vector bits (Repeat Message Request / Active Wakeup), and user
    // data; all other CBV bits left zero.
    std::vector<std::uint8_t> buildPdu() const;

    // True when this node's current Network Mode episode was actively requested by
    // itself (the Active Wakeup Bit it sets on tx; see kCbvActiveWakeup). Exposed so
    // a module / coordinator can read the local wake reason without parsing a PDU.
    bool activeWakeup() const { return active_wakeup_; }

    // True while this node is driving node detection it originated itself — i.e. the
    // Repeat Message Request bit it sets on tx (requestRepeatMessage() in Network
    // Mode, until the Repeat Message window elapses). A receiver re-entering Repeat
    // Message because of a *peer's* request does not set this — it does not
    // propagate the bit — so this reads "locally requested", not merely "in Repeat
    // Message". Exposed so a module can read the local node-detection state without
    // parsing a PDU.
    bool repeatMessageRequested() const { return repeat_requested_; }

    std::function<void(const std::vector<std::uint8_t>&)> onTransmit;   // module -> socket
    std::function<void(State from, State to)>             onTransition;  // optional observer

private:
    void transitionTo(State next);
    void transmit();

    Timing                    timing_;
    PduLayout                 layout_;
    std::uint8_t              node_id_;
    std::vector<std::uint8_t> user_data_;
    State                     state_ = State::kBusSleep;
    bool                      network_requested_ = false;
    bool                      repeat_requested_ = false;  // set RMR bit on tx while true
    bool                      active_wakeup_ = false;     // set Active Wakeup bit on tx while true
    std::chrono::milliseconds nm_timeout_rem_{0};
    std::chrono::milliseconds repeat_msg_rem_{0};
    std::chrono::milliseconds wait_bus_sleep_rem_{0};
    std::chrono::milliseconds msg_cycle_rem_{0};
};

}  // namespace tc8::nm
