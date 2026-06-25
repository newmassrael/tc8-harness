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

// NM PDU field layout (OEM config). Offsets are byte offsets within a PDU of
// pdu_length bytes. control_bit_vector_off is the wire position of the Control
// Bit Vector; this core machine validates its placement but leaves the byte zero
// — the CBV bits (repeat-message request, sleep-ready, ...) are not modeled here,
// so the offset documents the wire layout an OEM populates rather than driving
// behavior.
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

    // Advance the machine by `elapsed`; call periodically with a period finer
    // than the configured timers (AUTOSAR Nm_MainFunction model).
    void mainFunction(std::chrono::milliseconds elapsed);

    // Application user data placed into transmitted PDUs (truncated/zero-padded
    // to user_data_len).
    void setUserData(const std::uint8_t* data, std::size_t len);

    State state() const { return state_; }

    // Assemble the current NM PDU per the layout (source node id, a zero control
    // bit vector, user data).
    std::vector<std::uint8_t> buildPdu() const;

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
    std::chrono::milliseconds nm_timeout_rem_{0};
    std::chrono::milliseconds repeat_msg_rem_{0};
    std::chrono::milliseconds wait_bus_sleep_rem_{0};
    std::chrono::milliseconds msg_cycle_rem_{0};
};

}  // namespace tc8::nm
