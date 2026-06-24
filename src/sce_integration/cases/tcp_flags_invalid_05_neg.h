#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_flags_invalid_05_neg_common.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_flags_invalid_05_neg_sm.h"

namespace tc8::sce::cases {

using TcpFlagsInvalid05NegSM =
    ::SCE::Generated::tcp_flags_invalid_05_neg::tcp_flags_invalid_05_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.8.6.6 TCP_FLAGS_INVALID_05 phase 1: a conformant DUT in SYN-SENT
// MUST move to CLOSED on a SYN+ACK+RST carrying an acceptable ACK (RFC 793 §3.9 p67),
// cancelling its SYN retransmit. kTcpDropDisruptiveRst makes the lwIP netif input hook
// swallow the RST-bearing segment so lwIP never sees it, stays in SYN-SENT, and keeps
// retransmitting its SYN — the continued-SYN violation the positive's absence window forbids.
// The case passes only when that continued SYN (or a pure ACK) is observed. lwIP-only
// (kCapIngressFault). The CLOSED-transition property the egress field-fault seam cannot reach
// (a conformant DUT emits nothing here, so there is no DUT field to corrupt).
template <>
struct TestCaseTraits<cases::TcpFlagsInvalid05NegSM>
    : TcpIngressFaultNegBase<cases::TcpFlagsInvalid05NegSM> {
    static constexpr std::string_view kCaseId       = "TCP_FLAGS_INVALID_05_NEG";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_FLAGS_INVALID_05 phase 1: the lwIP kTcpDropDisruptiveRst "
        "ingress flavor drops a SYN+ACK+RST in SYN-SENT so the DUT keeps retransmitting its "
        "SYN; a conformant DUT moves to CLOSED and goes silent";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        cases::flags_invalid_05_neg::driveSynSentRstDrop(
            dut, cfg, iface,
            ::tc8::sce::tcp::kTcpFlagsInvalid05Phase1LocalOffset,
            ::tc8::stimulus::kTcpFlagSyn | ::tc8::stimulus::kTcpFlagAck
                | ::tc8::stimulus::kTcpFlagRst);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsInvalid05NegSM, tcp_flags_invalid_05_neg)
