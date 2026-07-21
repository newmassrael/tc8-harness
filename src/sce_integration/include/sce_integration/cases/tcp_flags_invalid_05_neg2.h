#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_flags_invalid_05_neg_common.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_flags_invalid_05_neg2_sm.h"

namespace tc8::sce::cases {

using TcpFlagsInvalid05Neg2SM =
    ::SCE::Generated::tcp_flags_invalid_05_neg2::tcp_flags_invalid_05_neg2;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.8.6.6 TCP_FLAGS_INVALID_05 phase 2: a conformant DUT in SYN-SENT
// MUST move to CLOSED on an ACK+RST carrying an acceptable ACK (RFC 793 §3.9 p67),
// cancelling its SYN retransmit. kTcpDropDisruptiveRst makes the lwIP netif input hook
// swallow the RST-bearing segment so lwIP never sees it, stays in SYN-SENT, and keeps
// retransmitting its SYN — the continued-SYN violation the positive's absence window forbids.
// The case passes only when that continued SYN (or a pure ACK) is observed. lwIP-only
// (kCapIngressFault). Twin of TCP_FLAGS_INVALID_05_NEG, differing only in the phase-2 flag set
// (ACK+RST, no SYN bit) and active-OPEN port offset.
template <>
struct TestCaseTraits<cases::TcpFlagsInvalid05Neg2SM>
    : TcpIngressFaultNegBase<cases::TcpFlagsInvalid05Neg2SM> {
    static constexpr std::string_view kCaseId       = "TCP_FLAGS_INVALID_05_NEG2";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_FLAGS_INVALID_05 phase 2: the lwIP kTcpDropDisruptiveRst "
        "ingress flavor drops an ACK+RST in SYN-SENT so the DUT keeps retransmitting its "
        "SYN; a conformant DUT moves to CLOSED and goes silent";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        cases::flags_invalid_05_neg::driveSynSentRstDrop(
            dut, cfg, iface,
            ::tc8::sce::tcp::kTcpFlagsInvalid05Phase2LocalOffset,
            ::tc8::stimulus::kTcpFlagAck | ::tc8::stimulus::kTcpFlagRst);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsInvalid05Neg2SM, tcp_flags_invalid_05_neg2)
