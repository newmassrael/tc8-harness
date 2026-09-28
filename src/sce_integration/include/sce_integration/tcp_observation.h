#pragma once

#include <cstdint>
#include <variant>

#include "tc8/captured_event.h"

#include "stimulus_observation.h"

namespace tc8::sce::tcp {

// Observation predicates over the DUT's TCP segments, for a stimulus that needs a
// segment the DUT sends before it can build its next one — typically the DUT's SYN
// or SYN+ACK, whose sequence number that next segment must acknowledge. Used with
// IStimulusObserver::awaitObservation before the listen window and with
// IStimulusScheduler::reactToObservation inside it.
//
// They read the case's own capture. The stimulus-private capture handle these
// replace (TcpFrameSnippet, removed with docs/tech-debt.md TD-60) was a second
// view of the wire with its own filter and no saved pcap, so a segment it waited on
// was not one the evidence records.
//
// The DUT is identified by `TestConfig::dut.ip`, the address the stimulus
// targets, and not by `cfg.ipv4.dut_iface_ip`, which is an EXPECTATION that
// negative rows deliberately flip. Keying the wait on the flipped value would make
// a negative row miss the DUT's own segment and never provoke the behaviour it
// exists to grade. 0 matches nothing, so the wait is reported unmet rather than
// satisfied by an unknown sender.

inline constexpr std::uint8_t kSynAckMask = 0x12;  // SYN | ACK

// The DUT's SYN (SYN set, ACK clear) from its local port `dut_port`: the first
// segment of an active open the DUT was asked to make.
inline ObservationPredicate dutSynFrom(std::uint32_t dut_ip_be, std::uint16_t dut_port) {
    return [dut_ip_be, dut_port](const ::tc8::CapturedEvent &ev) {
        const auto *t = std::get_if<::tc8::TcpFrame>(&ev);
        return t != nullptr && dut_ip_be != 0U && t->src_ip == dut_ip_be &&
               t->src_port == dut_port && (t->flags & kSynAckMask) == 0x02;
    };
}

// The DUT's SYN+ACK to the tester port `tester_port`: its answer to a SYN the
// tester injected from that port.
inline ObservationPredicate dutSynAckTo(std::uint32_t dut_ip_be, std::uint16_t tester_port) {
    return [dut_ip_be, tester_port](const ::tc8::CapturedEvent &ev) {
        const auto *t = std::get_if<::tc8::TcpFrame>(&ev);
        return t != nullptr && dut_ip_be != 0U && t->src_ip == dut_ip_be &&
               t->dst_port == tester_port && (t->flags & kSynAckMask) == kSynAckMask;
    };
}

// The TCP segment of an event a TCP predicate matched. Such an event is always a
// TcpFrame, so this cannot fail for one returned by the waits above.
inline const ::tc8::TcpFrame &segmentOf(const ::tc8::CapturedEvent &ev) {
    return std::get<::tc8::TcpFrame>(ev);
}

}  // namespace tc8::sce::tcp
