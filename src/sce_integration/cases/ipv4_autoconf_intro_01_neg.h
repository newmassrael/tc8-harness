#pragma once

#include <string_view>

#include "tc8/bpf_group.h"
#include "tc8/captured_event.h"
#include "tc8/upper_tester_protocol.h"

#include "sce_integration/arp_and_dhcpv4_captured.h"
#include "sce_integration/arp_and_dhcpv4_expected.h"
#include "sce_integration/arp_and_dhcpv4_pilot_common.h"
#include "sce_integration/case_registry.h"
#include "sce_integration/dhcpv4_pilot_common.h"
#include "sce_integration/dhcpv4_server_stimulus.h"
#include "sce_integration/test_case_traits.h"
#include "sce_integration/test_runner.h"

#include "ipv4_autoconf_intro_01_neg_sm.h"

namespace tc8::sce::cases {

using Ipv4AutoconfIntro01NegSM =
    ::SCE::Generated::ipv4_autoconf_intro_01_neg::ipv4_autoconf_intro_01_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4AutoconfIntro01NegSM> {
    using SM    = cases::Ipv4AutoconfIntro01NegSM;
    using State = SM::PolicyType::State;
    using Event = SM::PolicyType::Event;

    static constexpr std::string_view kCaseId =
        "IPv4_AUTOCONF_INTRO_01_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of INTRO_01: tc8-dut leaks an IPv4 Link-Local "
        "ARP Probe while holding a DHCP lease (RFC 3927 §1.9 SHOULD NOT)";
    static constexpr bool             kDeprecated = false;
    static constexpr int              kTopology   = 1;
    static constexpr ::tc8::BpfGroup  kBpfGroup   = ::tc8::BpfGroup::ArpAndDhcpv4;

    using Captured = typename SM::CapturedType;
    using Expected = typename SM::ExpectedType;

    // Same spec-mandated lease (ParamListenTime*3 = 15 s) as the
    // positive _01 so the DUT genuinely holds a routable lease when the
    // prohibited link-local Probe leaks. See ipv4_autoconf_intro_01.h
    // for the immediately-invoked-lambda rationale (ServerEmulParams is
    // non-literal).
    static inline const ::tc8::sce::dhcpv4::ServerEmulParams kIntroParams = []() {
        ::tc8::sce::dhcpv4::ServerEmulParams p{};
        p.lease_time_seconds = 15U;
        return p;
    }();

    // Mirror the positive _01 DHCP lifecycle (OFFER on
    // Listening_for_request entry, ACK on Listening_for_ll_probe entry),
    // but drive it with the LeakLinkLocalAfterBind flavor: tc8-dut's DHCP
    // client binds the lease and then AUTONOMOUSLY emits one prohibited
    // 169.254/16 ARP Probe (RFC 3927 §1.9 SHOULD NOT). The leak is a real
    // firmware code path gated by the flavor, so a conformant tc8-dut
    // (flavor None) stays silent — the negative's fail_compliant_silence
    // branch is the live conformant-DUT outcome, not a harness artifact.
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::dhcpv4::emitStartDhcpClientBuggy(
            cfg, iface, cfg.dut.mac,
            ::tc8::ut::kDhcpFlavorLeakLinkLocalAfterBind);

        ::tc8::sce::dhcpv4::scheduleDhcpReplyOnStateEntry(
            scheduler, static_cast<int>(State::Listening_for_request),
            iface, c.dhcpv4, /*message_type=*/2, kIntroParams);

        ::tc8::sce::dhcpv4::scheduleDhcpReplyOnStateEntry(
            scheduler, static_cast<int>(State::Listening_for_ll_probe),
            iface, c.dhcpv4, /*message_type=*/5, kIntroParams);
    }

    static void dispatch(Captured& c, SM& sm,
                         const ::tc8::CapturedEvent& ev) {
        ::tc8::sce::dispatchArpAndDhcpv4Frame<SM>(c, sm, ev);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4AutoconfIntro01NegSM,
                  ipv4_autoconf_intro_01_neg)
