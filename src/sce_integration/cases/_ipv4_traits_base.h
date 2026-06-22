#pragma once

#include "tc8/bpf_group.h"
#include "tc8/captured_event.h"

#include "sce_integration/dut_capabilities.h"
#include "sce_integration/ipv4_fragments_common.h"
#include "sce_integration/ipv4_pilot_common.h"
#include "sce_integration/test_case_traits.h"

// Shared §4.4 IPv4 trait bases. Two siblings cover the two dispatch
// shapes that recur across the IPv4-only sub-cluster (HEADER / TTL /
// VERSION / CHECKSUM / ADDRESSING_03 + FRAGMENTS / REASSEMBLY):
//
//   - Ipv4ObservationBase<SM>          dispatchIpv4Frame helper, used by
//                                      14 cases observing the DUT's
//                                      Echo Reply / ICMP error reply
//                                      with malformed-IP-header probes
//                                      (HEADER_01..04/08/09, TTL_01/05,
//                                      VERSION_01/03/04, CHECKSUM_02/05,
//                                      ADDRESSING_03).
//   - Ipv4FragmentEchoBase<SM>         fragments::dispatchEchoReply
//                                      helper (type=0 narrowing), used
//                                      by 12 cases observing the DUT's
//                                      Echo Reply after IP reassembly
//                                      (FRAGMENTS_01..04,
//                                      REASSEMBLY_04/06/07/09..13).
//
// Both bases pin kBpfGroup=Icmpv4 because the DUT's reply for any
// IPv4-layer test is ICMP-shaped (Echo Reply, Time Exceeded, or
// Parameter Problem) — the BPF filter selects the ICMP traffic, the
// dispatch helpers extract the Ipv4Frame / Icmpv4Frame variant
// respectively.
//
// Cross-protocol cases are intentionally NOT migrated onto these bases:
//   - ADDRESSING_01/02 + FRAGMENTS_05 (UDP stimulus + UDP observation,
//     kBpfGroup=Udp) keep their verbatim traits using
//     udp::dispatchUdpFrame.
//   - HEADER_05 (limited-broadcast destination, ICMP-agnostic
//     observation) uses icmpv4::dispatchAnyIcmpFrame and stays
//     verbatim.
//
// §4.5 link-local autoconf cases (ipv4_autoconf_*.h) live in a
// different observation surface (ARP frames, kBpfGroup=Arp /
// ArpAndDhcpv4) and are out of scope here — see a future
// _ipv4_autoconf_traits_base.h refactor.
//
// Stimulus is intentionally NOT provided here — every §4.4 case has
// its own per-case stimulus (Echo Request with malformed header,
// fragment pair, broadcast-dst, ...) and `has_stimulus_v` SFINAE in
// test_case_traits.h would pick up an inherited base member, forcing
// kickStimulus() to fire on every case unconditionally.

namespace tc8::sce {

template <typename StateMachine>
struct Ipv4ObservationBase {
    using SM       = StateMachine;
    using State    = typename StateMachine::PolicyType::State;
    using Event    = typename StateMachine::PolicyType::Event;
    using Captured = typename StateMachine::CapturedType;
    using Expected = typename StateMachine::ExpectedType;

    static constexpr bool             kDeprecated = false;
    static constexpr int              kTopology   = 1;
    static constexpr ::tc8::BpfGroup  kBpfGroup   = ::tc8::BpfGroup::Icmpv4;

    static void dispatch(Captured& c, SM& sm, const ::tc8::CapturedEvent& ev) {
        ::tc8::sce::ipv4::dispatchIpv4Frame<SM>(c, sm, ev);
    }
};

template <typename StateMachine>
struct Ipv4FragmentEchoBase {
    using SM       = StateMachine;
    using State    = typename StateMachine::PolicyType::State;
    using Event    = typename StateMachine::PolicyType::Event;
    using Captured = typename StateMachine::CapturedType;
    using Expected = typename StateMachine::ExpectedType;

    static constexpr bool             kDeprecated = false;
    static constexpr int              kTopology   = 1;
    static constexpr ::tc8::BpfGroup  kBpfGroup   = ::tc8::BpfGroup::Icmpv4;

    static void dispatch(Captured& c, SM& sm, const ::tc8::CapturedEvent& ev) {
        ::tc8::sce::ipv4::fragments::dispatchEchoReply<SM>(c, sm, ev);
    }
};

// Base for the §4.4 IPv4-header EGRESS field-fault `_NEG` cases. Same Echo Reply
// observation as Ipv4ObservationBase, plus the one declaration every such case shares:
// it requires the DUT to implement OpSetEgressFlavor (kCapEgressFault). The Tier-2 gate
// runs these only on the lwIP fixture and capability-skips them (N/A) on the
// kernel-stack reference DUT — the IPv4 sibling of TcpEgressFaultNegBase.
template <typename StateMachine>
struct Ipv4EgressFaultNegBase : Ipv4ObservationBase<StateMachine> {
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapEgressFault;
};

}  // namespace tc8::sce
