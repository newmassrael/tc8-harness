#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_autoconf_traits_base.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_autoconf_announcing_06_neg_sm.h"

namespace tc8::sce::cases {

using Ipv4AutoconfAnnouncing06NegSM =
    ::SCE::Generated::ipv4_autoconf_announcing_06_neg::ipv4_autoconf_announcing_06_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4AutoconfAnnouncing06NegSM>
    : LinklocalAutoconfBase<cases::Ipv4AutoconfAnnouncing06NegSM> {
    static constexpr std::string_view kCaseId =
        "IPv4_AUTOCONF_ANNOUNCING_06_NEG";
    static constexpr std::string_view kSpecSection = "4.5.6.3";
    static constexpr std::string_view kDescription =
        "Self-validation of _06: tc8-dut fast announce_interval="
        "200 ms drives the Announce interval below the RFC 3927 §2.4 "
        "ANNOUNCE_INTERVAL-50ms tolerance window";

    // Cadence violation via the standard 0x0C opcode (fast envelope's
    // 200 ms announce_interval), not a flavor — the same data-not-code
    // pattern as ADDRESS_SELECTION_10_NEG for Probe cadence.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::linklocal::emitStartLLAutoconfFast(
            cfg, iface, cfg.dut.mac);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4AutoconfAnnouncing06NegSM,
                  ipv4_autoconf_announcing_06_neg)
