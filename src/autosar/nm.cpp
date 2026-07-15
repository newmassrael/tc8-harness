#include "tc8/autosar/nm.h"

#include <algorithm>
#include <stdexcept>

namespace tc8::nm {

namespace {
constexpr std::chrono::milliseconds kZero{0};
}  // namespace

StateMachine::StateMachine(Timing timing, PduLayout layout, std::uint8_t node_id)
    : timing_(timing), layout_(layout), node_id_(node_id), user_data_(layout.user_data_len, 0x00) {
    if (layout_.source_node_id_off >= layout_.pdu_length ||
        layout_.control_bit_vector_off >= layout_.pdu_length ||
        layout_.user_data_off + layout_.user_data_len > layout_.pdu_length) {
        throw std::invalid_argument("tc8::nm::StateMachine: PDU layout exceeds pdu_length");
    }
}

void StateMachine::transmit() {
    if (onTransmit) {
        onTransmit(buildPdu());
    }
    msg_cycle_rem_ = timing_.msg_cycle;
    nm_timeout_rem_ = timing_.msg_timeout;  // own tx restarts the NM-Timeout
}

void StateMachine::transitionTo(State next) {
    if (next == state_) {
        return;
    }
    const State from = state_;
    state_ = next;
    if (next != State::kRepeatMessage) {
        repeat_requested_ = false;  // the request bit lives only during Repeat Message
    }
    if (onTransition) {
        onTransition(from, next);
    }
    switch (next) {
        case State::kRepeatMessage:
            repeat_msg_rem_ = timing_.repeat_message;
            nm_timeout_rem_ = timing_.msg_timeout;
            transmit();  // NM tx starts on entering Network Mode
            break;
        case State::kNormalOperation:
            transmit();  // tx starts immediately when entering Normal Operation
            break;
        case State::kPrepareBusSleep:
            wait_bus_sleep_rem_ = timing_.wait_bus_sleep;
            break;
        case State::kReadySleep:   // no tx; the running NM-Timeout decides sleep
            break;
        case State::kBusSleep:
            active_wakeup_ = false;  // the active-wakeup indication clears on full sleep
            break;
    }
}

void StateMachine::requestNetwork() {
    network_requested_ = true;
    active_wakeup_ = true;  // a local request is an active wakeup -> set the CBV bit on tx
    if (state_ == State::kBusSleep || state_ == State::kPrepareBusSleep) {
        transitionTo(State::kRepeatMessage);
    } else if (state_ == State::kReadySleep) {
        transitionTo(State::kNormalOperation);
    }
}

void StateMachine::releaseNetwork() {
    network_requested_ = false;
    if (state_ == State::kNormalOperation) {
        transitionTo(State::kReadySleep);
    }
}

void StateMachine::requestRepeatMessage() {
    // Only meaningful in Network Mode; Bus Sleep / Prepare Bus Sleep have nothing
    // to repeat. Mark the request (so buildPdu sets the RMR bit) and re-enter — or,
    // if already there, restart — Repeat Message State.
    if (state_ != State::kNormalOperation && state_ != State::kReadySleep &&
        state_ != State::kRepeatMessage) {
        return;
    }
    repeat_requested_ = true;
    if (state_ == State::kRepeatMessage) {
        repeat_msg_rem_ = timing_.repeat_message;  // restart the bounded window
    } else {
        transitionTo(State::kRepeatMessage);
    }
}

void StateMachine::rxNmPdu(const std::uint8_t* pdu, std::size_t len) {
    nm_timeout_rem_ = timing_.msg_timeout;  // any received NM PDU restarts the NM-Timeout
    if (state_ == State::kBusSleep || state_ == State::kPrepareBusSleep) {
        transitionTo(State::kRepeatMessage);  // passive startup
        return;
    }
    // Node detection: a peer that set the Repeat Message Request bit makes every
    // receiver in Network Mode re-enter (or restart) Repeat Message State and
    // re-announce. The receiver does not set its own request bit — only the
    // originator does (repeat_requested_ stays false) — so the request does not
    // storm on a shared medium.
    if (len > layout_.control_bit_vector_off &&
        (pdu[layout_.control_bit_vector_off] & kCbvRepeatMessageRequest) != 0) {
        if (state_ == State::kRepeatMessage) {
            repeat_msg_rem_ = timing_.repeat_message;
        } else {  // Normal Operation or Ready Sleep
            transitionTo(State::kRepeatMessage);
        }
    }
}

void StateMachine::mainFunction(std::chrono::milliseconds elapsed) {
    // The NM-Timeout runs across Network Mode but is only acted on in Ready Sleep:
    // Repeat Message and Normal Operation transmit every msg_cycle, and each tx
    // restarts the NM-Timeout, so it can only elapse where there is no tx — Ready
    // Sleep — from which it drives the transition to Prepare Bus Sleep.
    switch (state_) {
        case State::kBusSleep:
            break;
        case State::kRepeatMessage:
            msg_cycle_rem_ -= elapsed;
            if (msg_cycle_rem_ <= kZero) {
                transmit();
            }
            repeat_msg_rem_ -= elapsed;
            if (repeat_msg_rem_ <= kZero) {
                transitionTo(network_requested_ ? State::kNormalOperation : State::kReadySleep);
            }
            break;
        case State::kNormalOperation:
            msg_cycle_rem_ -= elapsed;
            if (msg_cycle_rem_ <= kZero) {
                transmit();
            }
            break;
        case State::kReadySleep:
            nm_timeout_rem_ -= elapsed;
            if (nm_timeout_rem_ <= kZero) {
                transitionTo(State::kPrepareBusSleep);
            }
            break;
        case State::kPrepareBusSleep:
            wait_bus_sleep_rem_ -= elapsed;
            if (wait_bus_sleep_rem_ <= kZero) {
                transitionTo(State::kBusSleep);
            }
            break;
    }
}

void StateMachine::setUserData(const std::uint8_t* data, std::size_t len) {
    user_data_.assign(layout_.user_data_len, 0x00);
    const std::size_t n = std::min(len, layout_.user_data_len);
    for (std::size_t i = 0; i < n; ++i) {
        user_data_[i] = data[i];
    }
}

std::vector<std::uint8_t> StateMachine::buildPdu() const {
    std::vector<std::uint8_t> pdu(layout_.pdu_length, 0x00);
    pdu[layout_.source_node_id_off] = node_id_;
    // CBV bits this machine models: the Repeat Message Request bit while driving
    // node detection (Repeat Message State entered via requestRepeatMessage), and
    // the Active Wakeup bit while the node holds the bus awake by its own request.
    // The other CBV bits stay an OEM concern and are left zero.
    if (repeat_requested_ && state_ == State::kRepeatMessage) {
        pdu[layout_.control_bit_vector_off] |= kCbvRepeatMessageRequest;
    }
    if (active_wakeup_) {
        pdu[layout_.control_bit_vector_off] |= kCbvActiveWakeup;
    }
    for (std::size_t i = 0; i < layout_.user_data_len; ++i) {
        pdu[layout_.user_data_off + i] = user_data_[i];
    }
    return pdu;
}

}  // namespace tc8::nm
