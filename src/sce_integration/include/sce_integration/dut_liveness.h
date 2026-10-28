#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <variant>

#include "tc8/captured_event.h"

#include "sce_integration/stimulus_observation.h"
#include "sce_integration/test_config.h"
#include "stimulus/icmpv4_builder.h"

// Is the DUT still running? A robustness case whose pass criterion is "the DUT has
// not crashed" (TC8 TCP_MSS_OPTIONS_01/_05) needs an answer to that question which
// does not depend on the thing a crash takes away.
//
// The Upper Tester cannot give it: a crashed DUT stops answering it too, and an
// unanswered control call is the tester's loss (recorded as an unperformed
// stimulus), so a case built on it lands on inconclusive exactly when the DUT
// crashed. The case's own connection cannot either: a DUT may abort a connection
// attempt it cannot parse without a word, and that silence is not a crash.
//
// What does give it is a service every live host must provide, reached through the
// DUT's own stack: the ICMP Echo server (RFC 1122 section 3.2.2.6, MUST). After the
// malformed input the tester sends one Echo Request; a live DUT answers it, and its
// silence over ParamListenTime is the observed quiescence of a DUT that is no
// longer running. The request is addressed by identity (`cfg.tester`, `cfg.dut`),
// never by the expectations negative rows flip, and carries its own identifier so
// no other Echo exchange can answer it.

namespace tc8::sce::liveness {

// The Echo identifier of the liveness probe ("LV"); distinct from the ICMPv4 pilot's
// `kIcmpEchoId`, so a reply to some other Echo is never taken for this one.
inline constexpr std::uint16_t kLivenessEchoId = 0x4C56;

inline constexpr std::uint8_t kIcmpEchoReply = 0;

// Send the liveness Echo Request numbered `seq` to the DUT. A case that probes
// after each of several inputs numbers the probes, so each reply answers one
// input. A send failure is recorded by the raw-Ethernet primitive
// (reportTxFailed), so a probe that never left the tester cannot be graded as the
// DUT's silence.
inline void emitLivenessEcho(const ::tc8::TestConfig& cfg, std::string_view iface,
                             std::uint16_t seq) {
    ::tc8::stimulus::IcmpMessageSpec spec{};
    spec.dst_mac  = cfg.dut.mac;
    spec.src_ip   = cfg.tester.ip;
    spec.dst_ip   = cfg.dut.ip;
    spec.echo_id  = kLivenessEchoId;
    spec.echo_seq = seq;
    ::tc8::stimulus::emitIcmpMessage(iface, spec, ::tc8::stimulus::IcmpBootTiming{});
}

// The sequence number of the liveness probe a DUT Echo Reply answers, or 0 when
// the event is not one. The identifier and sequence number are the first and
// second 16-bit words of the ICMP rest-of-header, network order.
inline std::uint16_t livenessEchoReplySeq(const ::tc8::CapturedEvent& ev, std::uint32_t dut_ip_be) {
    const auto* f = std::get_if<::tc8::Icmpv4Frame>(&ev);
    if (f == nullptr || dut_ip_be == 0U || f->src_ip != dut_ip_be || f->type != kIcmpEchoReply) {
        return 0;
    }
    const std::uint32_t word = f->rest_of_header;
    if (static_cast<std::uint16_t>(word >> 16) != kLivenessEchoId) {
        return 0;
    }
    return static_cast<std::uint16_t>(word & 0xFFFFU);
}

inline ObservationPredicate livenessEchoReplyFrom(std::uint32_t dut_ip_be, std::uint16_t seq) {
    return [dut_ip_be, seq](const ::tc8::CapturedEvent& ev) {
        return seq != 0U && livenessEchoReplySeq(ev, dut_ip_be) == seq;
    };
}

// Probe after one malformed input from inside a stimulus: send the Echo numbered
// `seq` and wait up to `bound` for its reply. True when the DUT answered. Its
// silence is what the case grades, so the wait records nothing when the bound
// elapses (IStimulusObserver::observeWithin); a stimulus that gets false stops
// there, because every further DUT-control call would go unanswered and be
// recorded as the tester's loss, turning the crash into an inconclusive.
inline bool probeLiveness(const ::tc8::TestConfig& cfg, std::string_view iface,
                          IStimulusObserver& observer, std::uint16_t seq,
                          std::chrono::milliseconds bound) {
    const ObservationCursor before = observer.mark();
    emitLivenessEcho(cfg, iface, seq);
    return observer.observeWithin("dut_liveness_echo_reply", before,
                                  livenessEchoReplyFrom(cfg.dut.ip, seq), bound)
        .has_value();
}

}  // namespace tc8::sce::liveness
