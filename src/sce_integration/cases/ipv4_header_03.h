#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_traits_base.h"
#include "sce_integration/ipv4_pilot_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_header_03_sm.h"

namespace tc8::sce::cases {

using Ipv4Header03SM = ::SCE::Generated::ipv4_header_03::ipv4_header_03;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4Header03SM>
    : Ipv4ObservationBase<cases::Ipv4Header03SM> {
    static constexpr std::string_view kCaseId      = "IPV4_HEADER_03";
    static constexpr std::string_view kSpecSection = "4.4.4.1";
    static constexpr std::string_view kDescription =
        "DUT's ICMP Echo Reply carries an IPv4 header whose Source "
        "Address equals one of the DUT's defined IPv4 addresses";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::ipv4::emitStimulus(cfg, iface);
    }

    // HEADER_03 has no explicit "wrong source" fail branch because the
    // field being checked IS the src_addr — an IPv4 frame whose src_addr
    // differs from the expectation is indistinguishable from the tester
    // stimulus (which also has a non-DUT src_addr). Both simply fail to
    // match the positive guard and the SM waits for the next event.
    // `fail_timeout` therefore covers both "DUT emitted nothing" and
    // "DUT emitted with a wrong src_addr" — the `--negative` row flips
    // `expected.dut_iface_ip` to prove the mismatch lands here.
    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:         return "pass";
            case State::Fail_timeout: return "fail:no_dut_ipv4_packet_with_expected_source_address";
            default:                  return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Header03SM, ipv4_header_03)
