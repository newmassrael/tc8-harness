#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>

#include "sce_integration/dut_socket_control.h"
#include "sce_integration/udp_captured.h"

namespace tc8::sce::udp {

// What a receive question's answer becomes in the case's Captured context.
//
// The answer comes back from the seam call in-process (IUdpReceiveControl), on
// whichever backend gave it, so these fields hold it without a wire frame in
// between: an opcode reply body and a testability Event end in the same place. A
// case's stimulus calls these right after the seam call returns, and the state
// machine reads the fields once the runner's stimulus-settled hook has raised
// `receive_answered` (raiseReceiveAnswered below).

// The first receive window's findings, and the second's for the one case (UDP
// FIELDS_05) that observes two senders in turn.
struct ReceiveAnswerFields {
    bool          answered = false;
    std::uint8_t  received = 0;
    std::uint32_t src_ip = 0;
    std::uint16_t src_port = 0;
    std::uint16_t payload_len = 0;
    std::array<std::uint8_t, 16> payload_first16{};
};

// An answer the verdict may grade is one that observed the probe, or that proved a
// discard (a sentinel delivered, or the DUT's own received=0). A refusal, a lost
// request and a silence give no answer: the fields stay unanswered, the case ends
// on its deadline as inconclusive, and the recording decorator has already named
// the call that was not performed.
inline ReceiveAnswerFields receiveAnswerFrom(const DutUdpReceiveOutcome &outcome) {
    ReceiveAnswerFields a;
    if (outcome.received()) {
        // The probe is the only datagram the window delivers besides the sentinel;
        // if the DUT forwarded more than one, the first is the earliest arrival.
        const DutReceivedDatagram &d = outcome.datagrams.front();
        a.answered = true;
        a.received = 1;
        a.src_ip = d.source.addr_be;
        a.src_port = d.source.port;
        a.payload_len = d.full_len;
        const std::size_t n = std::min(d.payload.size(), a.payload_first16.size());
        std::copy_n(d.payload.begin(), n, a.payload_first16.begin());
    } else if (outcome.discarded()) {
        a.answered = true;
        a.received = 0;
    }
    return a;
}

// First window: the fields the cases' SCXML conds read as `ut_received`, `ut_recv_*`.
inline void recordReceiveAnswer(UdpCaptured &c, const DutUdpReceiveOutcome &outcome) {
    const ReceiveAnswerFields a = receiveAnswerFrom(outcome);
    c.receive_answered = a.answered;
    c.ut_received = a.received;
    c.ut_recv_src_ip = a.src_ip;
    c.ut_recv_src_port = a.src_port;
    c.ut_recv_payload_len = a.payload_len;
    c.ut_recv_payload_first16 = a.payload_first16;
}

// Second window (UDP_FIELDS_05's Host-2 sender): only what that case grades.
inline void recordSecondReceiveAnswer(UdpCaptured &c, const DutUdpReceiveOutcome &outcome) {
    const ReceiveAnswerFields a = receiveAnswerFrom(outcome);
    c.receive2_answered = a.answered;
    c.ut_received_p2 = a.received;
    c.ut_recv_src_ip_p2 = a.src_ip;
}

// UDP_USER_INTERFACE_01: how many ports the DUT reports it opened. nullopt (no
// answer, or a refusal) leaves the case unanswered.
inline void recordPortsAnswer(UdpCaptured &c, const std::optional<std::uint8_t> &opened) {
    c.receive_answered = opened.has_value();
    c.ut_create_actual_count = opened.value_or(0);
}

// Raise the event that lets the machine read the recorded answer. The runner calls
// the case's `onStimulusSettled` once, after the stimulus has returned; the machine
// declares `receive_answered` on the transitions that grade the answer.
template <typename SM>
inline void raiseReceiveAnswered(SM &sm) {
    sm.raiseExternal(SM::PolicyType::Event::Receive_answered);
    sm.step();
}

}  // namespace tc8::sce::udp
