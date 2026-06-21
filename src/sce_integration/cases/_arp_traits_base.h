#pragma once

#include <chrono>
#include <string_view>
#include <thread>
#include <variant>

#include "tc8/bpf_group.h"
#include "tc8/captured_event.h"

#include "sce_integration/arp_captured.h"
#include "sce_integration/dut_capabilities.h"
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
// Every §4.2 case — the positives AND the lwIP fault `_neg` self-validation
// siblings — is covered by these two DISPATCH shapes; no third dispatch shape is
// needed. (The ArpFaultNeg*Base mixins below are NOT third shapes: each inherits
// one of these two dispatches and only adds a capability declaration.) Stated by
// shape, not a frozen case count, so the claim survives the `_neg` track and
// future §4.2 additions.
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
                                                   cfg.dut.ip,
                                                   cfg.dut.mac, timing);
}

// §4.2.4.2 ARP_48/49 mid-stimulus cache-conditioning step (UT 0x17)
// for topologies whose DUT advertises OpConditionArpCache —
// `cfg.arp_stimulus.ut_cache_conditioning_s > 0` is the caller-side gate. Same
// UT-envelope identity rules as `emitArpEgressProvocation` above:
// TOPOLOGY values, never the SCXML-expectation knobs.
inline int emitArpCacheConditioning(const ::tc8::TestConfig &cfg, std::string_view iface,
                                    std::uint8_t action, std::uint16_t param) {
    return ::tc8::stimulus::emitConditionArpCache(iface, cfg.ipv4.tester_ip,
                                                  cfg.dut.ip,
                                                  cfg.dut.mac,
                                                  action, param);
}

// §4.2 ARP egress-fault arming (UT 0x18) for the ARP_07..12 / ARP_46/47 _neg
// self-validation cluster. Pays the boot bring-up wait BEFORE the one-shot arm
// lands — the lwIP UT server must be listening or the raw-injected arm is lost
// (mirroring `emitStartLLAutoconfBuggy`, the §4.5 analog). A non-None `flavor`
// makes the lwIP netif egress hook corrupt one RFC 826 header field of the next
// DUT-emitted ARP frame. lwIP-only: the kernel-backed reference DUT answers
// OpSetArpFlavor with kStatusUnknownOpcode, so the flavor stays inert and the
// cluster is expected:false on Linux (docs/spec/inventory_overrides.json).
// Same UT-envelope identity rules as `emitArpCacheConditioning` above: TOPOLOGY
// values, never the SCXML-expectation knobs.
inline void emitArpFlavorArm(const ::tc8::TestConfig &cfg, std::string_view iface,
                             std::uint8_t flavor) {
    if (cfg.stimulus_timing.initial_wait.count() > 0) {
        std::this_thread::sleep_for(cfg.stimulus_timing.initial_wait);
    }
    ::tc8::stimulus::emitSetArpFlavor(iface, cfg.ipv4.tester_ip, cfg.dut.ip,
                                      cfg.dut.mac, flavor);
}

// Request-shape _neg stimulus (ARP_07..12): arm the egress fault, then drive the
// same UT 0x02 egress provocation the positive case uses so the lwIP DUT emits a
// cache-miss ARP Request the hook corrupts. The provocation's own bring-up wait
// is suppressed — `emitArpFlavorArm` already paid it, and the UT server is now
// proven up — so the two emits do not double the pause. The deadline does not
// arm until kickStimulus returns (test_runner.h), so this whole block runs
// before the listen window opens and the corrupted Request is captured either
// way.
inline void emitArpFlavorRequestProvocation(const ::tc8::TestConfig &cfg,
                                            std::string_view iface,
                                            std::uint8_t flavor) {
    emitArpFlavorArm(cfg, iface, flavor);
    ::tc8::stimulus::BootTiming timing = cfg.stimulus_timing;
    timing.initial_wait = std::chrono::milliseconds{0};
    emitArpEgressProvocation(cfg, iface, timing);
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

// Base for the §4.2 ARP egress-fault `_NEG` self-validation cases (ARP_07..12 /
// 46/47). Adds the one declaration every such case shares: it requires the DUT
// to implement OpSetArpFlavor (kCapArpFlavor). The DUT is the SSOT for that —
// OpcodeUtControl::capabilities() derives kCapArpFlavor from the DUT's
// OpQueryCapabilities (0x16) bitmap — so the Tier-2 gate runs these only where
// the fault seam exists (the lwIP fixture) and capability-skips them (N/A, not
// a fail) on the kernel-stack reference DUT, with no per-case inventory entry.
template <typename StateMachine>
struct ArpFaultNegBase : ArpAnyBase<StateMachine> {
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapArpFlavor;
};

// Same capability mixin over the ArpFrame+UdpFrame dispatch shape (#2), for the
// §4.2.4.2 drop-and-emit `_NEG` cases (ARP_22/28/38) whose pass path observes a
// UDP carrier. Not a third dispatch shape — it inherits ArpAndUdpBase's dispatch
// and only adds the kCapArpFlavor declaration (the sibling of ArpFaultNegBase).
template <typename StateMachine>
struct ArpFaultNegUdpBase : ArpAndUdpBase<StateMachine> {
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapArpFlavor;
};

}  // namespace tc8::sce
