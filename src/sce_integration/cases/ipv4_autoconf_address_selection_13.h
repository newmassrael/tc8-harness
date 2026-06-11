#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_autoconf_traits_base.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_autoconf_address_selection_13_sm.h"

namespace tc8::sce::cases {

using Ipv4AutoconfAddressSelection13SM =
    ::SCE::Generated::ipv4_autoconf_address_selection_13::ipv4_autoconf_address_selection_13;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4AutoconfAddressSelection13SM>
    : LinklocalProbeSnapshotBase<cases::Ipv4AutoconfAddressSelection13SM> {
    static constexpr std::string_view kCaseId =
        "IPv4_AUTOCONF_ADDRESS_SELECTION_13";
    static constexpr std::string_view kSpecSection = "4.5.6.2";
    static constexpr std::string_view kDescription =
        "DUT re-picks LL address after probing-window conflict ARP "
        "Probe (RFC 3927 §2.2.1, MUST)";

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         linklocal::IStimulusScheduler& scheduler) {
        ::tc8::sce::linklocal::emitStartLLAutoconfFast(
            cfg, iface, cfg.dut.mac);
        ::tc8::sce::linklocal::scheduleConflictArpOnStateEntry(
            scheduler, static_cast<int>(State::Await_repick),
            iface, ::tc8::sce::linklocal::ConflictArpVariant::Probe, c);
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

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4AutoconfAddressSelection13SM,
                  ipv4_autoconf_address_selection_13)
