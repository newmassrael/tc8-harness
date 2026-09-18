#pragma once

#include <chrono>
#include <string_view>
#include <thread>
#include <variant>

#include "tc8/bpf_group.h"
#include "tc8/captured_event.h"

#include "sce_integration/arp_captured.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/dut_capabilities.h"
#include "tc8/unperformed_stimulus.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_case_traits.h"
#include "sce_integration/test_config.h"
#include "stimulus/upper_tester_client.h"

// Shared §4.2 ARP trait bases. Two siblings cover the two dispatch
// shapes that recur across the cluster:
//
//   - ArpAnyBase<SM>          ArpFrame-only dispatch — cases that observe
//                             only DUT-emitted ARP frames (kBpfGroup=Arp);
//                             a few (ARP_03/_05) share the ArpFrame-only
//                             dispatch but capture UDP stimulus alongside
//                             (kBpfGroup=ArpAndUdp, shadowed in the derived
//                             struct).
//   - ArpAndUdpBase<SM>       ArpFrame + UdpFrame dispatch — cases that
//                             observe both DUT-emitted ARP and the UDP
//                             carriers downstream (kBpfGroup=ArpAndUdp).
//                             Raises Event::Arp_observed on ArpFrame and
//                             Event::Udp_observed on UdpFrame; the SCXML
//                             guards discriminate.
//
// Every §4.2 case is covered by these two ArpFrame dispatch shapes, plus one
// narrowing for the drop-and-emit `_neg`: the ArpEgressFaultNegBase /
// ArpIngressFaultNegBase mixins just add a capability declaration over ArpAnyBase;
// ArpIngressFaultNegUdpBase (the §4.2.4.2 drop-and-emit cases) narrows ArpAndUdpBase
// to a UDP-ONLY dispatch because it must ignore the DUT's conformant control-plane
// ARP resolution (see the base below). Stated by shape, not a frozen case count, so
// the claim survives the `_neg` track and future §4.2 additions.
//
// A SECOND axis crosses those dispatch shapes: whether the case DRIVES the DUT
// over the Tier-2 seam or only observes what the tester provokes from the wire.
// Driving needs `IArpControl`, so those cases declare kCapArpConditioning and the
// gate can decline a backend that has none — ArpDutProvokedBase (ArpFrame-only)
// and ArpEgressFaultNegProvokedBase (its fault-armed sibling) carry it, and
// ArpAndUdpBase carries it for all of its cases. The axis is separate because
// the two are independent: ArpAnyBase has 28 cases and only 11 drive the DUT.
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
// Routed over the Tier-2 seam. The UT-envelope identity rules above now hold in
// ONE place — the backend was built with them — instead of being restated at
// every call. Returns the send's status, 0 on success, as before.
inline int emitArpEgressProvocation(::tc8::sce::IDutControl &dut,
                                    const ::tc8::stimulus::BootTiming &timing) {
    auto *arp = dut.arpControl();
    if (arp == nullptr) {
        // The backend cannot provoke the DUT, so no ARP Request is coming. Left
        // unnamed this produced `no_arp_request_within_listen_window` — a
        // non-conclusion that reads like a DUT fault. Naming it points at the
        // step that did not happen instead. The gate should have skipped the case
        // first (kCapArpConditioning); this is what keeps a case that forgot the
        // declaration honest rather than silent.
        ::tc8::UnperformedStimulus::record("dut_arp_control_absent");
        return -1;
    }
    return arp->provokeEgress(timing);
}

// §4.2.4.2 ARP_48/49 mid-stimulus cache-conditioning step (UT 0x17)
// for topologies whose DUT advertises OpConditionArpCache —
// `cfg.arp_stimulus.ut_cache_conditioning_s > 0` is the caller-side gate. Same
// UT-envelope identity rules as `emitArpEgressProvocation` above:
// TOPOLOGY values, never the SCXML-expectation knobs.
inline int emitArpCacheConditioning(::tc8::sce::IDutControl &dut,
                                    std::uint8_t action, std::uint16_t param) {
    auto *arp = dut.arpControl();
    if (arp == nullptr) {
        ::tc8::UnperformedStimulus::record("dut_arp_control_absent");
        return -1;
    }
    return arp->conditionCache(action, param);
}

// emitEgressFlavorArm / emitIngressFlavorArm (the generic UT 0x18 / 0x19 arming)
// live in _fault_flavor_arm.h — they are mechanism-generic (ARP egress 07..12 /
// 46/47 and ingress 21/27/37/42 + 22/28/38 here; UDP and beyond elsewhere).

// Request-shape egress _neg stimulus (ARP_07..12): arm the egress fault, then drive
// the same UT 0x02 egress provocation the positive case uses so the lwIP DUT emits a
// cache-miss ARP Request the hook corrupts. The provocation's own bring-up wait is
// suppressed — `emitEgressFlavorArm` already paid it, and the UT server is now
// proven up — so the two emits do not double the pause. The deadline does not arm
// until kickStimulus returns (test_runner.h), so this whole block runs before the
// listen window opens and the corrupted Request is captured either way.
inline void emitEgressFlavorRequestProvocation(const ::tc8::TestConfig &cfg,
                                               std::string_view iface,
                                               ::tc8::sce::IDutControl &dut,
                                               std::uint8_t flavor) {
    emitEgressFlavorArm(cfg, iface, flavor);
    ::tc8::stimulus::BootTiming timing = cfg.stimulus_timing;
    timing.initial_wait = std::chrono::milliseconds{0};
    emitArpEgressProvocation(dut, timing);
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

    // Every case on this base drives the DUT through IArpControl (the UT 0x02
    // egress provocation, and for ARP_48/49 the 0x17 cache conditioning), so it
    // is only measurable on a backend that provides that sub-interface.
    //
    // Without the declaration the gate cannot fire, and on a backend without it
    // `emitArpEgressProvocation` returns -1, the DUT is never provoked, and the
    // case sits out its listen window and reports `no_arp_request_within_...` —
    // a non-conclusion that reads like a DUT fault when the truth is that the
    // stimulus never happened. Measured on the AUTOSAR testability backend,
    // whose capabilities() is kCapTcpControl|kCapUdpControl alone.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapArpConditioning;

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

// Base for the §4.2 cases that DRIVE the DUT over the seam while observing ARP
// alone — the UT 0x02 egress provocation, and ARP_48/49's 0x17 cache
// conditioning. Same ArpFrame dispatch as ArpAnyBase, plus the declaration that
// makes the capability gate able to fire.
//
// Separate from ArpAnyBase rather than folded into it because only 11 of that
// base's 28 cases drive the DUT at all; the rest observe traffic the tester
// provokes from the wire and are measurable on any backend. Declaring the
// requirement on ArpAnyBase would capability-skip those 17 for a sub-interface
// they never touch, which trades one wrong non-conclusion for another.
template <typename StateMachine>
struct ArpDutProvokedBase : ArpAnyBase<StateMachine> {
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapArpConditioning;
};

// Base for the §4.2 ARP EGRESS field-fault `_NEG` cases (ARP_07..12 / 46/47). Adds
// the one declaration every such case shares: it requires the DUT to implement
// OpSetEgressFlavor (kCapEgressFault). The DUT is the SSOT for that —
// OpcodeUtControl::capabilities() derives kCapEgressFault from the DUT's
// OpQueryCapabilities (0x16) bitmap — so the Tier-2 gate runs these only where the
// fault seam exists (the lwIP fixture) and capability-skips them (N/A, not a fail)
// on the kernel-stack reference DUT, with no per-case inventory entry.
template <typename StateMachine>
struct ArpEgressFaultNegBase : ArpAnyBase<StateMachine> {
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapEgressFault;
};

// The Request-shape half of that family (ARP_07..12): after arming the fault it
// drives the SAME UT 0x02 provocation the positive cases use, so it needs the
// seam as well as the fault opcode. Its two siblings (ARP_46/47_NEG) arm the
// fault and then inject the stimulus ARP from the TESTER, touching no
// sub-interface — which is why this is a separate base and not an amendment to
// ArpEgressFaultNegBase.
template <typename StateMachine>
struct ArpEgressFaultNegProvokedBase : ArpAnyBase<StateMachine> {
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapEgressFault | ::tc8::sce::kCapArpConditioning;
};

// Base for the §4.2.4.2 reply-absence INGRESS `_NEG` cases (ARP_21/27/37/42). Same
// ArpFrame dispatch as the egress base, but requires the ingress seam
// (kCapIngressFault ↔ OpSetIngressFlavor) instead.
template <typename StateMachine>
struct ArpIngressFaultNegBase : ArpAnyBase<StateMachine> {
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapIngressFault;
};

// Base for the §4.2.4.2 drop-and-emit INGRESS `_NEG` cases (ARP_22/28/38). These
// observe ONLY the UDP egress MAC, so they dispatch UdpFrame alone: on the lwIP
// fixture the DUT ARP-resolves the tester for its own UT control-plane ACKs (no
// DUT-side neigh pin, unlike the Linux reference DUT), and that opcode-1 ARP Request
// is conformant traffic indistinguishable from a conformant egress resolution —
// useless as a discriminator. Only the egress that adopted the injected MAC proves
// the fault took. Inherits ArpAndUdpBase for the constants + aliases (kBpfGroup
// stays ArpAndUdp so the ARP frames are still captured for the pcap/evidence) and
// OVERRIDES dispatch to UDP-only; the base's ArpFrame dispatch is never odr-used, so
// its Arp_observed reference is never instantiated. Requires kCapIngressFault.
template <typename StateMachine>
struct ArpIngressFaultNegUdpBase : ArpAndUdpBase<StateMachine> {
    using Base = ArpAndUdpBase<StateMachine>;
    using typename Base::SM;
    using typename Base::Event;
    using typename Base::Captured;

    // Shadows ArpAndUdpBase's declaration rather than extending it, so the seam
    // bit has to be restated here — dropping it would silently un-gate the very
    // provocation these cases depend on.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapIngressFault | ::tc8::sce::kCapArpConditioning;

    static void dispatch(Captured& c, SM& sm, const ::tc8::CapturedEvent& ev) {
        if (const auto* u = std::get_if<::tc8::UdpFrame>(&ev)) {
            ::tc8::fillArpCapturedFromUdpFrame(c, *u);
            sm.raiseExternal(Event::Udp_observed);
            sm.step();
        }
    }
};

}  // namespace tc8::sce
