#pragma once

#include "tc8/bpf_group.h"
#include "tc8/captured_event.h"

#include "sce_integration/arp_and_dhcpv4_pilot_common.h"
#include "sce_integration/dhcpv4_pilot_common.h"
#include "sce_integration/test_case_traits.h"
#include "sce_integration/udp_and_dhcpv4_pilot_common.h"

// Shared §4.7 DHCPv4 trait bases. Three siblings cover the dispatch
// shapes that recur across the cluster:
//
//   - Dhcpv4AnyBase<SM>           dispatchDhcpv4Frame helper
//                                 (kBpfGroup=Dhcpv4) — 45 cases observe
//                                 only DUT-emitted DHCPv4 frames
//                                 (DISCOVER / REQUEST / DECLINE / ...).
//   - Dhcpv4ArpBase<SM>           dispatchArpAndDhcpv4Frame helper
//                                 (kBpfGroup=ArpAndDhcpv4) — 5 cases
//                                 observe DUT ARP Probes alongside
//                                 DHCPv4 traffic (post-DHCPACK ARP
//                                 Probe, init-allocation declaration).
//   - Dhcpv4UdpBase<SM>           dispatchUdpAndDhcpv4Frame helper
//                                 (kBpfGroup=UdpAndDhcpv4) — 2 cases
//                                 (CONSTRUCTING_MESSAGES_05/_06) need
//                                 to observe UDP-as-such alongside the
//                                 DHCPv4 decode for protocol-fields
//                                 invariants.
//
// Stimulus is intentionally NOT provided here — every §4.7 case has its
// own per-case stimulus shape (StartDhcpClient, server-side DISCOVER /
// OFFER / ACK / NAK injection, ARP-Probe response, ...) and
// `has_stimulus_v` SFINAE in test_case_traits.h would pick up an
// inherited base member, forcing kickStimulus() to fire on every case.

namespace tc8::sce {

template <typename StateMachine>
struct Dhcpv4AnyBase {
    using SM       = StateMachine;
    using State    = typename StateMachine::PolicyType::State;
    using Event    = typename StateMachine::PolicyType::Event;
    using Captured = typename StateMachine::CapturedType;
    using Expected = typename StateMachine::ExpectedType;

    static constexpr bool             kDeprecated = false;
    static constexpr int              kTopology   = 1;
    static constexpr ::tc8::BpfGroup  kBpfGroup   = ::tc8::BpfGroup::Dhcpv4;

    static void dispatch(Captured& c, SM& sm, const ::tc8::CapturedEvent& ev) {
        ::tc8::sce::dhcpv4::dispatchDhcpv4Frame<SM>(c, sm, ev);
    }
};

template <typename StateMachine>
struct Dhcpv4ArpBase : Dhcpv4AnyBase<StateMachine> {
    using Base = Dhcpv4AnyBase<StateMachine>;
    using typename Base::SM;
    using typename Base::Captured;

    static constexpr ::tc8::BpfGroup kBpfGroup = ::tc8::BpfGroup::ArpAndDhcpv4;

    static void dispatch(Captured& c, SM& sm, const ::tc8::CapturedEvent& ev) {
        ::tc8::sce::dispatchArpAndDhcpv4Frame<SM>(c, sm, ev);
    }
};

template <typename StateMachine>
struct Dhcpv4UdpBase : Dhcpv4AnyBase<StateMachine> {
    using Base = Dhcpv4AnyBase<StateMachine>;
    using typename Base::SM;
    using typename Base::Captured;

    static constexpr ::tc8::BpfGroup kBpfGroup = ::tc8::BpfGroup::UdpAndDhcpv4;

    static void dispatch(Captured& c, SM& sm, const ::tc8::CapturedEvent& ev) {
        ::tc8::sce::dispatchUdpAndDhcpv4Frame<SM>(c, sm, ev);
    }
};

}  // namespace tc8::sce
