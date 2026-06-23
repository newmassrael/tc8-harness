#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_autoconf_traits_base.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_autoconf_network_partitions_01_neg2_sm.h"

namespace tc8::sce::cases {

using Ipv4AutoconfNetworkPartitions01Neg2SM =
    ::SCE::Generated::ipv4_autoconf_network_partitions_01_neg2::ipv4_autoconf_network_partitions_01_neg2;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4AutoconfNetworkPartitions01Neg2SM>
    : LinklocalAutoconfBase<cases::Ipv4AutoconfNetworkPartitions01Neg2SM> {
    static constexpr std::string_view kCaseId =
        "IPv4_AUTOCONF_NETWORK_PARTITIONS_01_NEG2";
    static constexpr std::string_view kDescription =
        "Self-validation of NETWORK_PARTITIONS_01 guard 2 (periodic "
        "gratuitous): tc8-dut EmitPeriodicGratuitous fault-injection "
        "re-emits the gratuitous ARP after the claim (RFC 3927 §4)";

    // Same claim-condition wiring as guard 1 / the positive, but the
    // stimulus carries EmitPeriodicGratuitous: the defending Reply stays
    // compliant (so the run passes post_claim) and tc8-dut's steady-state
    // loop re-emits the Announce-shaped gratuitous ARP that the
    // listening_no_periodic guard witnesses. Proves guard 2
    // (fail_periodic_gratuitous_arp) is reachable.
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::linklocal::emitStartLLAutoconfBuggy(
            cfg, iface, cfg.dut.mac,
            ::tc8::ut::kFlavorEmitPeriodicGratuitous);
        ::tc8::sce::linklocal::scheduleClaimConditionTesterRequest(
            scheduler, static_cast<int>(State::Listening_post_claim),
            cfg, iface, c);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4AutoconfNetworkPartitions01Neg2SM,
                  ipv4_autoconf_network_partitions_01_neg2)
