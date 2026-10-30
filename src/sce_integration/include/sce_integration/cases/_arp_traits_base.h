#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <variant>
#include <vector>

#include "stimulus/boot_timing.h"
#include "tc8/bpf_group.h"
#include "tc8/captured_event.h"

#include "sce_integration/arp_captured.h"
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
// ArpFaultNegUdpBase (the §4.2.4.2 drop-and-emit cases) narrows ArpAndUdpBase
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
// dst=<HOST-1-IP>)" as a boot-cadence UDP send through the seam. A free function
// (not a base member — see the SFINAE note above) so per-case `stimulus` bodies
// compose it with their injections.
//
// It is a UDP send, not an ARP operation, so it rides IUdpControl: a backend that
// can send a datagram can provoke, whether or not it can also age the ARP cache.
// The datagram is the one `isEgressProvocationDatagram` recognises (DUT
// `kEgressBootDutSrcPort` to the tester's `ut::kDataPort`), and it goes to the
// TOPOLOGY tester address (`cfg.tester.ip`), never the `arp.tester_ip` SCXML
// expectation knob — a `--negative` override must shift only the SCXML
// comparison, not silence the DUT. Returns 0 when every emit was done, as the
// boot cadence does (stimulus/boot_timing.h).
// Payload content carries no verdict weight (§4.2 guards compare dst_ip + Eth-dst
// only); a recognisable literal helps pcap readers.
inline const std::vector<std::uint8_t> &egressProvocationPayload() {
    static const std::vector<std::uint8_t> kPayload{'T', 'C', '8', '-', 'E', 'G',
                                                    'R', 'E', 'S', 'S'};
    return kPayload;
}

inline int emitArpEgressProvocation(::tc8::sce::IDutControl &dut,
                                    const ::tc8::TestConfig &cfg,
                                    const ::tc8::stimulus::BootTiming &timing) {
    auto *udp = dut.udpControl();
    if (udp == nullptr) {
        // The backend cannot make the DUT send, so no ARP Request is coming. Left
        // unnamed this produced `no_arp_request_within_listen_window` — a
        // non-conclusion that reads like a DUT fault. Naming it points at the
        // step that did not happen instead. The gate should have skipped the case
        // first (kCapUdpControl); this is what keeps a case that forgot the
        // declaration honest rather than silent.
        ::tc8::UnperformedStimulus::record("dut_udp_control_absent");
        return -1;
    }
    return ::tc8::stimulus::runBootCadence(timing, [&](int /*attempt*/) {
        return udp->sendDatagram(
                   Endpoint{/*addr_be=*/0, ::tc8::stimulus::kEgressBootDutSrcPort},
                   Endpoint{cfg.tester.ip, ::tc8::ut::kDataPort}, egressProvocationPayload())
                   ? 0
                   : -1;
    });
}

// The provocation for a case that holds the DUT's ARP cache COLD for the tester
// (ARP_39/40: the tester teaches the DUT only after the DUT has had to ask). The
// DUT's answer to the request is queued behind the resolution the case provokes
// next, so it cannot be waited for; the datagram the DUT was asked to send is what
// the wire shows. Gate the case on kCapUdpUnacknowledgedSend.
inline int emitArpColdCacheProvocation(::tc8::sce::IDutControl &dut,
                                       const ::tc8::TestConfig &cfg,
                                       const ::tc8::stimulus::BootTiming &timing) {
    auto *udp = dut.udpControl();
    if (udp == nullptr) {
        ::tc8::UnperformedStimulus::record("dut_udp_control_absent");
        return -1;
    }
    return ::tc8::stimulus::runBootCadence(timing, [&](int /*attempt*/) {
        return udp->sendDatagramUnacknowledged(
                   Endpoint{/*addr_be=*/0, ::tc8::stimulus::kEgressBootDutSrcPort},
                   Endpoint{cfg.tester.ip, ::tc8::ut::kDataPort}, egressProvocationPayload())
                   ? 0
                   : -1;
    });
}

// §4.2.4.2 ARP_48/49 mid-stimulus cache-aging step, for topologies whose DUT can
// age its ARP cache — `cfg.arp_stimulus.ut_cache_conditioning_s > 0` is the
// caller-side gate. Gate the case on kCapArpConditioning.
inline int emitArpCacheAge(::tc8::sce::IDutControl &dut, std::uint16_t seconds) {
    auto *arp = dut.arpControl();
    if (arp == nullptr) {
        ::tc8::UnperformedStimulus::record("dut_arp_control_absent");
        return -1;
    }
    return arp->ageCacheBySeconds(seconds);
}

// Install / take out a permanent DUT ARP entry — TC8 §4.2.3's configuration and
// cleanup operations (UT 0x17 AddStatic / RemoveStatic), for the same topologies as
// `emitArpCacheAge` — gate the case on kCapArpConditioning. The entry is
// the case's to name: pass the address and MAC the procedure pins (its HOST-1 IP
// and the MAC it expects the DUT to address), never the SCXML expectation knobs.
inline int emitArpStaticEntryAdd(::tc8::sce::IDutControl &dut, std::uint32_t ip_be,
                                 const std::array<std::uint8_t, 6> &mac) {
    auto *arp = dut.arpControl();
    if (arp == nullptr) {
        ::tc8::UnperformedStimulus::record("dut_arp_control_absent");
        return -1;
    }
    return arp->addStaticEntry(ip_be, mac);
}

inline int emitArpStaticEntryRemove(::tc8::sce::IDutControl &dut, std::uint32_t ip_be) {
    auto *arp = dut.arpControl();
    if (arp == nullptr) {
        ::tc8::UnperformedStimulus::record("dut_arp_control_absent");
        return -1;
    }
    return arp->removeStaticEntry(ip_be);
}

// emitEgressFlavorArm / emitIngressFlavorArm (the generic UT 0x18 / 0x19 arming) live
// in _fault_flavor_arm.h — mechanism-generic (ARP egress 07..12 / 46/47 and ingress
// 21/27/37/42 + 22/28/38; UDP and beyond elsewhere). The one ARP-shaped composition of
// them, emitEgressFlavorRequestProvocation, lives in _arp_fault_arm.h.
//
// ⚠ This file deliberately does NOT include either. It is the base EVERY §4.2 case
// uses, positive and negative alike, and the arm header carries the fault-flavour
// catalogue: including it here put the catalogue in all 64 ARP cases, which the MD5
// bucketing then spread over every registrar chunk — measured 2026-09-25, that alone
// undid the TD-44 split (23 of 25 chunks still rebuilt on a catalogue change). Six
// case headers needed that composition; all 806 were paying for it.

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

// Whether `u` is the datagram the egress provocation asked for (UT 0x02, DUT
// `kEgressBootDutSrcPort` → tester `ut::kDataPort`) — the only UDP a §4.2 case
// grades. Every UDP case on these bases reads its verdict off "the DUT's UDP
// to the tester": pass when its Ethernet destination is the learned MAC, fail
// when it is not. Identified by destination IP alone, ANY datagram the DUT sends
// the tester decides that — measured on a DUT with its own service traffic: a
// SOME/IP event datagram, sent to the tester through the very ARP entry under
// test, met the guard five frames before the provoked one. Against a reference
// DUT that sends the tester nothing else this never shows; against a real ECU
// it decides the verdict. The port pair is the provocation's own identity, and
// no fault flavor these cases arm rewrites it (kEthFaultUdpEgressDstWrong touches
// only the Ethernet destination).
inline bool isEgressProvocationDatagram(const ::tc8::UdpFrame &u) {
    return u.src_port == ::tc8::stimulus::kEgressBootDutSrcPort &&
           u.dst_port == ::tc8::ut::kDataPort;
}

template <typename StateMachine>
struct ArpAndUdpBase : ArpAnyBase<StateMachine> {
    using Base = ArpAnyBase<StateMachine>;
    using typename Base::SM;
    using typename Base::Event;
    using typename Base::Captured;

    static constexpr ::tc8::BpfGroup kBpfGroup = ::tc8::BpfGroup::ArpAndUdp;

    // Every case on this base provokes the DUT with a UDP send through the seam
    // (`emitArpEgressProvocation`), so it is only measurable on a backend that
    // provides IUdpControl. ARP_48/49 also age the DUT's ARP cache and declare
    // kCapArpConditioning beside it.
    //
    // Without the declaration the gate cannot fire, and on a backend without it
    // `emitArpEgressProvocation` returns -1, the DUT is never provoked, and the
    // case sits out its listen window and reports `no_arp_request_within_...` —
    // a non-conclusion that reads like a DUT fault when the truth is that the
    // stimulus never happened.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapUdpControl;

    static void dispatch(Captured& c, SM& sm, const ::tc8::CapturedEvent& ev) {
        if (const auto* f = std::get_if<::tc8::ArpFrame>(&ev)) {
            ::tc8::fillArpCapturedFromFrame(c, *f);
            sm.raiseExternal(Event::Arp_observed);
            sm.step();
            return;
        }
        if (const auto* u = std::get_if<::tc8::UdpFrame>(&ev)) {
            if (!isEgressProvocationDatagram(*u)) {
                return;  // the DUT's other traffic to the tester is not the egress under test
            }
            ::tc8::fillArpCapturedFromUdpFrame(c, *u);
            sm.raiseExternal(Event::Udp_observed);
            sm.step();
            return;
        }
    }
};

// Base for the §4.2 cases that DRIVE the DUT over the seam while observing ARP
// alone — the UDP egress provocation. Same ArpFrame dispatch as ArpAnyBase, plus
// the declaration that makes the capability gate able to fire.
//
// Separate from ArpAnyBase rather than folded into it because only 11 of that
// base's 28 cases drive the DUT at all; the rest observe traffic the tester
// provokes from the wire and are measurable on any backend. Declaring the
// requirement on ArpAnyBase would capability-skip those 17 for a sub-interface
// they never touch, which trades one wrong non-conclusion for another.
template <typename StateMachine>
struct ArpDutProvokedBase : ArpAnyBase<StateMachine> {
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapUdpControl;
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
    // Unacknowledged send: the fault corrupts the Request the DUT resolves the
    // tester with, so its reply to the provocation never comes (_arp_fault_arm.h).
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapEgressFault | ::tc8::sce::kCapUdpControl |
        ::tc8::sce::kCapUdpUnacknowledgedSend;
};

// Base for the §4.2.4.2 reply-absence INGRESS `_NEG` cases (ARP_21/27/37/42). Same
// ArpFrame dispatch as the egress base, but requires the ingress seam
// (kCapIngressFault ↔ OpSetIngressFlavor) instead.
template <typename StateMachine>
struct ArpIngressFaultNegBase : ArpAnyBase<StateMachine> {
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapIngressFault;
};

// Base for the §4.2.4.1 cache-staleness INGRESS `_NEG` cases, which arm
// kArpFaultIgnoreLearn / kArpFaultIgnoreUpdate and then PROVOKE an egress over the
// seam. Two seams, so two bits: the ingress flavor is what makes the teaching not
// take, and the provocation is what gives the DUT a reason to resolve at all.
//
// Dispatches ArpFrame (inherited from ArpAnyBase), unlike the drop-and-emit sibling
// below, and that difference is deliberate. There the DUT's own control-plane ARP
// Request is indistinguishable from the behaviour under test, so it cannot be the
// discriminator. Here it IS the behaviour under test: these cases teach the DUT an
// address first, so a conformant run never needs to resolve it — every opcode-1
// Request from the DUT means the teaching did not take, which is exactly what the
// positive's `dut_arp_request_after_*` final forbids.
template <typename StateMachine>
struct ArpIngressFaultNegProvokedBase : ArpAnyBase<StateMachine> {
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapIngressFault | ::tc8::sce::kCapUdpControl;
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
// its Arp_observed reference is never instantiated.
//
// `FaultSeam` is the fixture seam the variant's fault rides on, named by each consumer
// rather than defaulted: kCapIngressFault for the cases that swallow a teaching frame
// before etharp sees it, kCapEgressFault for the ones that corrupt what the DUT emits.
// It carries no default on purpose — the comment below is about a bit that goes missing
// silently, and a default is the shape that lets it.
template <typename StateMachine, ::tc8::sce::DutCapabilities FaultSeam>
struct ArpFaultNegUdpBase : ArpAndUdpBase<StateMachine> {
    using Base = ArpAndUdpBase<StateMachine>;
    using typename Base::SM;
    using typename Base::Event;
    using typename Base::Captured;

    // Shadows ArpAndUdpBase's declaration rather than extending it, so the seam
    // bit has to be restated here — dropping it would silently un-gate the very
    // provocation these cases depend on. kCapUdpControl is not part of the
    // parameter because it is what the egress provocation itself needs, whichever
    // seam the fault uses.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        FaultSeam | ::tc8::sce::kCapUdpControl;

    static void dispatch(Captured& c, SM& sm, const ::tc8::CapturedEvent& ev) {
        if (const auto* u = std::get_if<::tc8::UdpFrame>(&ev)) {
            if (!isEgressProvocationDatagram(*u)) {
                return;  // see isEgressProvocationDatagram
            }
            ::tc8::fillArpCapturedFromUdpFrame(c, *u);
            sm.raiseExternal(Event::Udp_observed);
            sm.step();
        }
    }
};

}  // namespace tc8::sce
