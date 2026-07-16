#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string_view>
#include <variant>
#include <vector>

#include "tc8/captured_event.h"
#include "sce_integration/icmpv4_captured.h"
#include "sce_integration/test_config.h"
#include "stimulus/icmpv4_builder.h"

namespace tc8::sce::icmpv4 {

// Per-case overrides for the §4.3 ICMPv4 pilot stimulus. All fields
// are optional; unset fields keep the `IcmpMessageSpec` defaults —
// which produce a well-formed Echo Request the DUT's kernel accepts
// and replies to. Populate a field to test a specific path:
//
//   * icmp_type / icmp_code       — §4.3.3.2 TYPE_16 (type=15 Info
//                                   Request → DUT must not reply).
//   * ip_protocol                 — §4.3.3.2 TYPE_18 (unsupported
//                                   protocol → Destination Unreachable).
//   * dst_mac                     — §4.3.3.2 TYPE_05/TYPE_18,
//                                   §4.3.3.1 ERROR_02/03, §4.3.3.2
//                                   TYPE_04: L2-unicast required
//                                   for error-class ICMP emission
//                                   (Linux `icmp_send` PACKET_HOST
//                                   gate) or for drop-reason
//                                   isolation.
//   * ip_options                  — §4.3.3.2 TYPE_05, §4.3.3.1
//                                   ERROR_02/03/04 (malformed or
//                                   length-12 Internet Timestamp).
//   * dst_ip                      — §4.3.3.1 ERROR_04 (broadcast
//                                   destination).
//   * more_fragments / fragment_offset / raw_ip_payload —
//                                   §4.3.3.1 ERROR_02/03, §4.3.3.2
//                                   TYPE_04: IPv4 fragmentation
//                                   stimulus. raw_ip_payload carries
//                                   a notional slice of a larger
//                                   ICMP packet for fragments with
//                                   offset != 0 or the sole TYPE_04
//                                   fragment.
//   * post_send_wait              — §4.3.3.2 TYPE_04: block the
//                                   stimulus until the DUT's IP
//                                   reassembly timer elapses.
//   * corrupt_icmp_checksum       — §4.3.3.2 TYPE_10 (flip ICMP
//                                   checksum; DUT drops silently).
//   * payload                     — §4.3.3.2 TYPE_08 (27 B spec
//                                   literal must echo back verbatim).
//
// Mirror of `ipv4_pilot_common.h::StimulusOverrides` — same POD shape
// so traits at this layer follow a consistent pattern across §4.3
// and §4.4. Add fields, don't add constructors.
struct StimulusOverrides {
    std::optional<std::uint8_t>   icmp_type;
    std::optional<std::uint8_t>   icmp_code;
    // §4.3.3.2 TYPE_18 — IPv4 Protocol byte override so the DUT
    // receives a packet with no registered L4 handler and replies with
    // ICMP Destination Unreachable / Protocol Unreachable. Applied at
    // IPv4 header level, not the ICMP header.
    std::optional<std::uint8_t>   ip_protocol;
    // L2 destination MAC. Default is Ethernet broadcast (builder
    // default) which works for Echo Request since Linux's icmp_echo
    // handler replies regardless of pkt_type. It does NOT work for
    // the ICMP error path (`icmp_send` in net/ipv4/icmp.c gates on
    // `skb->pkt_type == PACKET_HOST` before emitting Destination
    // Unreachable / Parameter Problem / Time Exceeded). §4.3.3.2
    // TYPE_18 and §4.3.3.1 ERROR_02 require unicast for the DUT's
    // error reply to emerge at all; §4.3.3.2 TYPE_05 and the
    // absence-shape §4.3.3.1 ERROR_03 + §4.3.3.2 TYPE_04 set it
    // defensively so L2-dispatch skew isn't a confounder for the
    // observed behaviour. See `reference_icmp_packet_host_gate.md`.
    std::optional<std::array<std::uint8_t, 6>> dst_mac;
    // §4.3.3.2 TYPE_05 / §4.3.3.1 ERROR_04 — IPv4 options bytes the
    // builder inserts between the fixed IPv4 header and the ICMP body.
    // Both cases pass `kIcmpv4TimestampOptionMalformed` (8 B, see
    // `stimulus/icmpv4_builder.h`). Empty default keeps the canonical
    // IHL=5 path for every other §4.3 consumer.
    std::vector<std::uint8_t>     ip_options;
    // §4.3.3.1 ERROR_04 — tester sends ICMP Echo Request to the IPv4
    // broadcast address (255.255.255.255 or subnet-directed). The DUT
    // must not reply with ICMP Parameter Problem even though the
    // options are malformed, per RFC 1122 §3.2.2. Default unset keeps
    // the stimulus pointed at `cfg.icmpv4.dut_iface_ip`.
    std::optional<std::uint32_t>  dst_ip;
    bool                          corrupt_icmp_checksum = false;
    // §4.3.3.1 ERROR_02/03 + §4.3.3.2 TYPE_04 — IPv4 fragmentation
    // flags. MF=1 marks a non-last fragment; `fragment_offset` is in
    // 8-octet units per RFC 791 §3.1. Defaults (MF=0, offset=0)
    // preserve the non-fragmented canonical emission for every other
    // §4.3 stimulus.
    bool                          more_fragments        = false;
    std::uint16_t                 fragment_offset       = 0;
    // §4.3.3.1 ERROR_03 frag 1 + §4.3.3.2 TYPE_04 — raw IP-payload
    // bytes that replace the builder's ICMP header + payload
    // synthesis. See `IcmpMessageSpec::raw_ip_payload` for rationale:
    // these fragments notionally carry the middle/tail of an ICMP
    // packet and do not have an ICMP header of their own. Empty
    // default keeps the ICMP-synthesis path for every other caller.
    std::vector<std::uint8_t>     raw_ip_payload;
    // §4.3.3.2 TYPE_04 — block the stimulus thread for this many
    // seconds AFTER the frame is on the wire. The tester must hold
    // off opening the SCXML listen window until the DUT's IP
    // fragment reassembly timer has expired (spec §4.3.1
    // `<FragReassemlyTimeout>` default 15 s; Linux
    // `net.ipv4.ipfrag_time` default 30 s) so any DUT-emitted
    // Time Exceeded has had its natural opportunity to emerge.
    // Migrated from `std::chrono::seconds` so FRAGMENTS_02/03/04 can
    // pair a sub-second phase-gap wait with smoke-test.sh's per-netns
    // `ipfrag_time=3 s` sysctl. `std::chrono::seconds{N}` converts
    // implicitly, so TYPE_04's 30 s wait is unchanged.
    std::chrono::milliseconds     post_send_wait{0};
    const std::uint8_t*           payload_data          = nullptr;
    std::uint32_t                 payload_len           = 0;
    // §4.3.3.2 TYPE_11 / TYPE_12 — ICMP Timestamp Request originate
    // value. Threaded into `IcmpMessageSpec::timestamp_originate` when
    // set; the builder switches to the Timestamp body shape only when
    // `icmp_type` is also 13 (RFC 792 p17 type byte). Default unset
    // keeps the canonical Echo Request emission for every other §4.3
    // consumer. Receive / Transmit slots stay at 0 on the wire per
    // RFC 792 — the Reply path is what fills them — so neither needs
    // a per-case override knob today.
    std::optional<std::uint32_t>  timestamp_originate;
};

// Emit one ICMPv4 message from the tester, with optional per-field
// overrides. Default-constructed `ov` reproduces the pilot's good-path
// stimulus (Echo Request, id=kIcmpEchoId, seq=kIcmpEchoSeq, empty
// payload) — the DUT's kernel replies with an Echo Reply the SCXML
// observes.
inline void emitStimulus(const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         const StimulusOverrides& ov = {}) {
    ::tc8::stimulus::IcmpMessageSpec spec{};
    spec.src_ip   = cfg.icmpv4.tester_ip;
    spec.dst_ip   = ov.dst_ip.value_or(cfg.icmpv4.dut_iface_ip);
    spec.echo_id  = ::tc8::stimulus::kIcmpEchoId;
    spec.echo_seq = ::tc8::stimulus::kIcmpEchoSeq;
    if (ov.icmp_type)   spec.icmp_type_override    = ov.icmp_type;
    if (ov.icmp_code)   spec.icmp_code_override    = ov.icmp_code;
    if (ov.ip_protocol) spec.ip_protocol_override  = ov.ip_protocol;
    if (ov.dst_mac)     spec.dst_mac               = *ov.dst_mac;
    spec.ip_options = ov.ip_options;
    spec.more_fragments  = ov.more_fragments;
    spec.fragment_offset = ov.fragment_offset;
    spec.raw_ip_payload  = ov.raw_ip_payload;
    spec.corrupt_icmp_checksum = ov.corrupt_icmp_checksum;
    spec.payload_data = ov.payload_data;
    spec.payload_len  = ov.payload_len;
    if (ov.timestamp_originate) {
        spec.timestamp_originate = *ov.timestamp_originate;
    }
    ::tc8::stimulus::IcmpBootTiming timing{};
    // Unconditional forward — `chrono::seconds{0}` default collapses
    // to the no-op wait path in emitIcmpMessage, so there is no
    // behavioural difference vs conditionally assigning. Keeping
    // this terse makes it obvious that post_send_wait is the only
    // timing knob surfaced at the per-case layer today.
    timing.post_send_wait = ov.post_send_wait;
    ::tc8::stimulus::emitIcmpMessage(iface, spec, timing);
}

// Dispatch helper: select the Icmpv4Frame variant from the captured
// event, filter to `expected_reply_type`, mirror its fields into `c`,
// and raise the shared `Icmp_observed` external event on the SM.
//
// Every type-specific §4.3 case has exactly one DUT-originated reply
// type of interest (type=0 Echo Reply for TYPE_08/09/10/22; type=16
// Information Reply for TYPE_16; type=3 Destination Unreachable for
// TYPE_18). The BPF "icmp" filter passes the tester's own outbound
// frames too, so narrowing here keeps SCXML guards focused on the
// reply semantics instead of the tester-egress noise.
template <typename SM>
inline void dispatchIcmpFrame(typename SM::CapturedType& c, SM& sm,
                              const ::tc8::CapturedEvent& ev,
                              std::uint8_t expected_reply_type) {
    const auto* f = std::get_if<::tc8::Icmpv4Frame>(&ev);
    if (f == nullptr) return;
    if (f->type != expected_reply_type) return;
    ::tc8::fillIcmpv4CapturedFromFrame(c, *f);
    const auto state_before = sm.getCurrentState();
    sm.raiseExternal(SM::PolicyType::Event::Icmp_observed);
    sm.step();
    const auto state_after = sm.getCurrentState();
    if (state_after != state_before) {
        c.snapshotFired();
    }
}

// Type-agnostic dispatch for §4.3.3.1 ERROR_05 ("unknown ICMP type
// silently discarded"). Spec: "DUT: Do not send any ICMP Message" —
// any type counts as a fail, so we cannot narrow by expected reply
// type. The SCXML's fail-transition conjuncts
// `captured.src_ip == expected.dut_iface_ip` instead, which excludes
// the tester's own outbound unknown-type frame that the BPF "icmp"
// filter also captures. Dispatch therefore fires `icmp_observed` for
// every ICMP frame on the wire and leaves origin filtering to the
// SCXML — mirrors TYPE_22's pass-guard pattern on the fail side.
template <typename SM>
inline void dispatchAnyIcmpFrame(typename SM::CapturedType& c, SM& sm,
                                 const ::tc8::CapturedEvent& ev) {
    const auto* f = std::get_if<::tc8::Icmpv4Frame>(&ev);
    if (f == nullptr) return;
    ::tc8::fillIcmpv4CapturedFromFrame(c, *f);
    const auto state_before = sm.getCurrentState();
    sm.raiseExternal(SM::PolicyType::Event::Icmp_observed);
    sm.step();
    const auto state_after = sm.getCurrentState();
    if (state_after != state_before) {
        c.snapshotFired();
    }
}

}  // namespace tc8::sce::icmpv4
