#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_user_interface_08_sm.h"

namespace tc8::sce::cases {

using UdpUserInterface08SM = ::SCE::Generated::udp_user_interface_08::udp_user_interface_08;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::UdpUserInterface08SM>
    : UdpDutOriginatedBase<cases::UdpUserInterface08SM> {
    static constexpr std::string_view kCaseId      = "UDP_USER_INTERFACE_08";
    static constexpr std::string_view kDescription =
        "DUT-emit UDP datagram carries caller-specified Destination IP "
        "Address (RFC 768 'User Interface' MUST)";

    // §4.6.5.5 UI_08 spec axis: TESTER asks DUT to emit a UDP message
    // with dst=`<AIface-0-IP>` — the tester's interface IP. With a
    // single primary IP per side the axis vacuously passes; the
    // tester's SECOND address makes it observable. Stimulus passes that
    // address as `target_ip_be`; the DUT egress UDP carries dst_ip=it
    // iff the DUT honoured the caller's choice. The SCXML cond gates the
    // pass branch on `captured.dst_ip == expected.tester_alias_ip` — a
    // buggy DUT that silently emits to the primary tester_ip lands on
    // `fail_wrong_dst_ip`.
    //
    // ⚠ The ask reads `cfg.tester.secondary_ip`, the address this tester
    // actually holds, and NOT the compiled `kTesterAliasIp4Be`: a host-NIC site
    // names its own tester alias, which moved the grading while the constant
    // kept asking for 172.16.0.4, so the DUT was told to send where nobody was
    // listening (docs/tech-debt.md TD-49).
    //
    // ⚠ And NOT `cfg.ipv4.tester_alias_ip`, which holds the same value: that one
    // is the EXPECTATION a `--negative ipv4.tester_alias_ip=…` row flips to prove
    // this guard is load-bearing. Reading the ask from it would move both sides
    // together and make that negative vacuous.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view /*iface*/,
                         ::tc8::sce::IDutControl& dut) {
        ::tc8::sce::udp::emitTriggerSendUdp(
            dut,
            /*dut_src_port=*/20028,
            /*target_ip_be=*/cfg.tester.secondary_ip,
            /*target_port=*/::tc8::sce::udp::kDataPort,
            ::tc8::sce::udp::kUdpDefaultData.data(),
            static_cast<std::uint16_t>(::tc8::sce::udp::kUdpDefaultData.size()));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpUserInterface08SM, udp_user_interface_08)
