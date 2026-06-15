#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_protocol_01_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientProtocol01SM =
    ::SCE::Generated::dhcpv4_client_protocol_01::dhcpv4_client_protocol_01;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientProtocol01SM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientProtocol01SM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_PROTOCOL_01";
    static constexpr std::string_view kSpecSection = "4.7.6.2";
    static constexpr std::string_view kDescription =
        "DHCPDISCOVER carries the RFC 1497 magic cookie 99,130,83,99 in "
        "the first four octets of the 'options' field (RFC 2131 §3, MUST)";
    // Single-step stimulus: kick the tc8-dut LL state machine via
    // OpStartLLAutoconf with the fast envelope. tc8-dut emits one
    // DHCPDISCOVER (the precondition step "DUT: Sends DHCPDISCOVER
    // Message") then enters PROBE phase per RFC 3927 §2.2.1 — the
    // PROBE phase is on the ARP wire, the BPF `udp port 67/68`
    // filter excludes it, so this SCXML's listening state only sees
    // the one DISCOVER.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::linklocal::emitStartLLAutoconfFast(
            cfg, iface, cfg.dut.mac);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientProtocol01SM,
                  dhcpv4_client_protocol_01)
