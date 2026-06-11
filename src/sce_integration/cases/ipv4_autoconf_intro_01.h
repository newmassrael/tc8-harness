#pragma once

#include <string_view>

#include "tc8/bpf_group.h"
#include "tc8/captured_event.h"

#include "sce_integration/arp_and_dhcpv4_captured.h"
#include "sce_integration/arp_and_dhcpv4_expected.h"
#include "sce_integration/arp_and_dhcpv4_pilot_common.h"
#include "sce_integration/case_registry.h"
#include "sce_integration/dhcpv4_pilot_common.h"
#include "sce_integration/dhcpv4_server_stimulus.h"
#include "sce_integration/test_case_traits.h"
#include "sce_integration/test_runner.h"

#include "ipv4_autoconf_intro_01_sm.h"

namespace tc8::sce::cases {

using Ipv4AutoconfIntro01SM =
    ::SCE::Generated::ipv4_autoconf_intro_01::ipv4_autoconf_intro_01;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4AutoconfIntro01SM> {
    using SM    = cases::Ipv4AutoconfIntro01SM;
    using State = SM::PolicyType::State;
    using Event = SM::PolicyType::Event;

    static constexpr std::string_view kCaseId =
        "IPv4_AUTOCONF_INTRO_01";
    static constexpr std::string_view kSpecSection = "4.5.6.1";
    static constexpr std::string_view kDescription =
        "DUT does not assign IPv4 Link-Local address when DHCP-bound "
        "routable address is available (RFC 3927 §1.9 SHOULD NOT)";
    static constexpr bool             kDeprecated = false;
    static constexpr int              kTopology   = 1;
    static constexpr ::tc8::BpfGroup  kBpfGroup   = ::tc8::BpfGroup::ArpAndDhcpv4;

    using Captured = typename SM::CapturedType;
    using Expected = typename SM::ExpectedType;

    // Spec: lease_time_seconds = ParamListenTime*3 = 15 s (TC8 RFC 3927 §3
    // ParamListenTime default is 5 s). Override the server emul
    // defaults so this case ships the spec-mandated lease without
    // mutating ServerEmulParams' static defaults (which other §4.7
    // cases consume verbatim).
    //
    // Constructed as an inline static via an immediately-invoked
    // lambda — `ServerEmulParams` carries `std::vector` payload
    // members for §4.7.6.7 CM_05/_06 Option Overload, which makes
    // the type non-literal. The lambda lets us preserve the named-
    // field initialisation pattern without spelling a free helper
    // function.
    static inline const ::tc8::sce::dhcpv4::ServerEmulParams kIntroParams = []() {
        ::tc8::sce::dhcpv4::ServerEmulParams p{};
        p.lease_time_seconds = 15U;
        return p;
    }();

    // 4-arg stimulus: kick the DHCP client lifecycle, then register
    // OFFER on Listening_for_request entry and ACK on
    // Listening_for_no_arp_probe entry. The composition Captured
    // requires `c.dhcpv4` (xid + chaddr live there) be passed to the
    // server emul observer; the helper template deduces
    // `Captured = Dhcpv4Captured` from the sub-context reference.
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::dhcpv4::emitStartDhcpClient(
            cfg, iface, cfg.dut.mac);

        ::tc8::sce::dhcpv4::scheduleDhcpReplyOnStateEntry(
            scheduler, static_cast<int>(State::Listening_for_request),
            iface, c.dhcpv4, /*message_type=*/2, kIntroParams);

        ::tc8::sce::dhcpv4::scheduleDhcpReplyOnStateEntry(
            scheduler, static_cast<int>(State::Listening_for_no_arp_probe),
            iface, c.dhcpv4, /*message_type=*/5, kIntroParams);
    }

    static void dispatch(Captured& c, SM& sm,
                         const ::tc8::CapturedEvent& ev) {
        ::tc8::sce::dispatchArpAndDhcpv4Frame<SM>(c, sm, ev);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:
                return "pass";
            case State::Fail_no_discover:
                return "fail:no_dut_dhcp_discover_within_listen_window";
            case State::Fail_no_request:
                return "fail:no_dut_dhcp_request_after_offer";
            case State::Fail_dut_emitted_ll_probe:
                return "fail:dut_emitted_link_local_arp_probe_despite_routable_lease";
            default:
                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4AutoconfIntro01SM,
                  ipv4_autoconf_intro_01)
