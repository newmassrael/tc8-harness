#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_autoconf_traits_base.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_autoconf_address_selection_11_sm.h"

namespace tc8::sce::cases {

using Ipv4AutoconfAddressSelection11SM =
    ::SCE::Generated::ipv4_autoconf_address_selection_11::ipv4_autoconf_address_selection_11;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4AutoconfAddressSelection11SM>
    : LinklocalProbeSnapshotBase<cases::Ipv4AutoconfAddressSelection11SM> {
    static constexpr std::string_view kCaseId =
        "IPV4_AUTOCONF_ADDRESS_SELECTION_11";
    static constexpr std::string_view kSpecSection = "4.5.6.2";
    static constexpr std::string_view kDescription =
        "DUT re-picks LL address after probing-window ARP Request "
        "conflict (RFC 3927 §2.2.1, MUST)";

    // Compound stimulus: kick the LL state machine, then queue a
    // state-entry observer to inject the conflict ARP the moment
    // SCXML moves to await_repick (= immediately after the first
    // DUT Probe is observed). The observer reads
    // `c.first_probe_target_proto_ip` at fire time so the conflict
    // frame claims exactly the DUT's tentative LL.
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         linklocal::IStimulusScheduler& scheduler) {
        ::tc8::sce::linklocal::emitStartLLAutoconfFast(
            cfg, iface, cfg.arp.dut_real_mac);
        ::tc8::sce::linklocal::scheduleConflictArpOnStateEntry(
            scheduler, static_cast<int>(State::Await_repick),
            iface, ::tc8::sce::linklocal::ConflictArpVariant::Request, c);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:
                return "pass";
            case State::Fail_no_initial_probe:
                return "fail:no_arp_probe_after_ll_start";
            case State::Fail_no_repick:
                return "fail:dut_did_not_repick_after_conflict_arp";
            default:
                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4AutoconfAddressSelection11SM,
                  ipv4_autoconf_address_selection_11)
