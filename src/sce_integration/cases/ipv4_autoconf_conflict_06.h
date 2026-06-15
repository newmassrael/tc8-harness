#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_autoconf_traits_base.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_autoconf_conflict_06_sm.h"

namespace tc8::sce::cases {

using Ipv4AutoconfConflict06SM =
    ::SCE::Generated::ipv4_autoconf_conflict_06::ipv4_autoconf_conflict_06;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4AutoconfConflict06SM>
    : LinklocalAutoconfBase<cases::Ipv4AutoconfConflict06SM> {
    static constexpr std::string_view kCaseId =
        "IPv4_AUTOCONF_CONFLICT_06";
    static constexpr std::string_view kSpecSection = "4.5.6.4";
    static constexpr std::string_view kDescription =
        "DUT ceases claim and re-probes after two ARP Request "
        "conflicts on its committed LL (RFC 3927 §2.5, MUST)";

    // 4-arg stimulus: kick the LL state machine, then schedule a
    // state-entry observer keyed on Listening_post_claim. SCXML
    // transitions pre_claim → post_claim on the first DUT Announce
    // (claim confirmation); the observer fires on entry, queries the
    // committed LL, snapshots it into Captured, and emits two
    // conflicting ARP Requests with sender == target == committed LL
    // (spec step 9 + 11). The DUT's always-cease branch abandons the
    // LL on the first conflict; the SCXML asserts a fresh DUT Probe
    // with target ≠ snapshotted LL.
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::linklocal::emitStartLLAutoconfFast(
            cfg, iface, cfg.dut.mac);
        ::tc8::sce::linklocal::scheduleDefenderCeaseConflicts(
            scheduler,
            static_cast<int>(State::Listening_post_claim),
            iface, cfg, c,
            /*opcode1=*/0x0001,  // ARP Request
            /*opcode2=*/0x0001); // ARP Request
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4AutoconfConflict06SM,
                  ipv4_autoconf_conflict_06)
