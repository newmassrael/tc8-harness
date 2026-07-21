#pragma once

#include <cstdint>
#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_call_receive_05_neg_common.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"

#include "tcp_call_receive_05_neg2_sm.h"

namespace tc8::sce::cases {

using TcpCallReceive05Neg2SM =
    ::SCE::Generated::tcp_call_receive_05_neg2::tcp_call_receive_05_neg2;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.8.6.4 TCP_CALL_RECEIVE_05 (FIN fail-final): a conformant DUT in
// CLOSE-WAIT returns the queued data on a RECEIVE call and stays in CW without emitting a FIN
// before the application closes (RFC 793 §3.5). kTcpSynthFinOnDisruptive makes the lwIP netif
// input hook synthesize the prohibited FIN+ACK on the connection's 4-tuple when the PSH+FIN+ACK
// EST->CW trigger arrives, and the case passes only when that synthesized FIN+ACK is observed
// (proving the dut_emitted_fin_in_cw_without_close fail-final reachable). lwIP-only
// (kCapIngressFault). The DUT stack never sees the synthesized FIN+ACK (a fabricated
// DUT->tester frame), so the DUT's real CLOSE-WAIT behaviour is unchanged.
template <>
struct TestCaseTraits<cases::TcpCallReceive05Neg2SM>
    : TcpIngressFaultNegBase<cases::TcpCallReceive05Neg2SM> {
    static constexpr std::string_view kCaseId       = "TCP_CALL_RECEIVE_05_NEG2";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_CALL_RECEIVE_05: the lwIP kTcpSynthFinOnDisruptive ingress "
        "flavor makes the DUT emit a FIN in CLOSE-WAIT; a conformant DUT stays silent";

    // Mirrors the positive's prelude (active-OPEN to ESTABLISHED + PSH+FIN+ACK drives the DUT
    // into CLOSE-WAIT), with kTcpSynthFinOnDisruptive armed before the disruptive segment.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        cases::call_receive_05_neg::driveCwAndArm(
            dut, cfg, iface, ::tc8::ut::kTcpSynthFinOnDisruptive,
            ::tc8::sce::tcp::kTcpCallReceive05NegFinOffset);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpCallReceive05Neg2SM, tcp_call_receive_05_neg2)
