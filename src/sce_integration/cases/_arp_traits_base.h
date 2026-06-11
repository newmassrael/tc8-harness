#pragma once

#include <string_view>
#include <variant>

#include "tc8/bpf_group.h"
#include "tc8/captured_event.h"

#include "sce_integration/arp_captured.h"
#include "sce_integration/test_case_traits.h"
#include "sce_integration/test_config.h"
#include "stimulus/upper_tester_client.h"

// Shared §4.2 ARP trait bases. Two siblings cover the two dispatch
// shapes that recur across the cluster:
//
//   - ArpAnyBase<SM>          ArpFrame-only dispatch — 26 cases observe
//                             only DUT-emitted ARP frames (kBpfGroup=Arp)
//                             plus 2 cases (ARP_03/_05) that share the
//                             ArpFrame-only dispatch but capture UDP
//                             stimulus alongside (kBpfGroup=ArpAndUdp,
//                             shadowed in the derived struct).
//   - ArpAndUdpBase<SM>       ArpFrame + UdpFrame dispatch — 13 cases
//                             observe both DUT-emitted ARP and the
//                             UDP carriers downstream (kBpfGroup=
//                             ArpAndUdp). Raises Event::Arp_observed
//                             on ArpFrame and Event::Udp_observed on
//                             UdpFrame; the SCXML guards discriminate.
//
// The 41st case (verified via `--list-cases`) is covered by these two
// shapes — no third base needed.
//
// Stimulus is intentionally NOT provided here — every §4.2 case has its
// own per-case stimulus (ARP-learning probe, UT egress provocation, ...)
// and `has_stimulus_v` SFINAE in test_case_traits.h would pick up an
// inherited base member, forcing kickStimulus() to fire on every case.

namespace tc8::sce {

// Shared §4.2.4 egress-provocation step: the spec's "DUT CONFIGURE:
// Configure DUT to send a UDP Message from <DIface-0> (src=<DIface-0-IP>,
// dst=<HOST-1-IP>)" as a UT 0x02 boot emit. A free function (not a base
// member — see the SFINAE note above) so per-case `stimulus` bodies
// compose it with their injections.
//
// This is the single place that selects the UT envelope identities:
// TOPOLOGY values (`cfg.ipv4.tester_ip` + `cfg.arp.dut_real_*`), never
// the `arp.tester_ip` / `arp.dut_iface_*` SCXML-expectation knobs — a
// `--negative` override must shift only the SCXML comparison, not
// silence the DUT (see `emitTriggerSendUdpBoot` in
// stimulus/upper_tester_client.h for the full rationale).
inline int emitArpEgressProvocation(const ::tc8::TestConfig &cfg, std::string_view iface,
                                    const ::tc8::stimulus::BootTiming &timing) {
    return ::tc8::stimulus::emitTriggerSendUdpBoot(iface, cfg.ipv4.tester_ip,
                                                   cfg.arp.dut_real_ip,
                                                   cfg.arp.dut_real_mac, timing);
}

template <typename StateMachine>
struct ArpAnyBase {
    using SM       = StateMachine;
    using State    = typename StateMachine::PolicyType::State;
    using Event    = typename StateMachine::PolicyType::Event;
    using Captured = typename StateMachine::CapturedType;
    using Expected = typename StateMachine::ExpectedType;

    static constexpr bool             kDeprecated = false;
    static constexpr int              kTopology   = 1;
    static constexpr ::tc8::BpfGroup  kBpfGroup   = ::tc8::BpfGroup::Arp;

    static void dispatch(Captured& c, SM& sm, const ::tc8::CapturedEvent& ev) {
        if (const auto* f = std::get_if<::tc8::ArpFrame>(&ev)) {
            ::tc8::fillArpCapturedFromFrame(c, *f);
            sm.raiseExternal(Event::Arp_observed);
            sm.step();
            return;
        }
    }
};

template <typename StateMachine>
struct ArpAndUdpBase : ArpAnyBase<StateMachine> {
    using Base = ArpAnyBase<StateMachine>;
    using typename Base::SM;
    using typename Base::Event;
    using typename Base::Captured;

    static constexpr ::tc8::BpfGroup kBpfGroup = ::tc8::BpfGroup::ArpAndUdp;

    static void dispatch(Captured& c, SM& sm, const ::tc8::CapturedEvent& ev) {
        if (const auto* f = std::get_if<::tc8::ArpFrame>(&ev)) {
            ::tc8::fillArpCapturedFromFrame(c, *f);
            sm.raiseExternal(Event::Arp_observed);
            sm.step();
            return;
        }
        if (const auto* u = std::get_if<::tc8::UdpFrame>(&ev)) {
            ::tc8::fillArpCapturedFromUdpFrame(c, *u);
            sm.raiseExternal(Event::Udp_observed);
            sm.step();
            return;
        }
    }
};

}  // namespace tc8::sce
