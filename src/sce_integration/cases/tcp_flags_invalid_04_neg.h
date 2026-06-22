#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_flags_invalid_04_neg_sm.h"

namespace tc8::sce::cases {

using TcpFlagsInvalid04NegSM =
    ::SCE::Generated::tcp_flags_invalid_04_neg::tcp_flags_invalid_04_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.8.6.6 TCP_FLAGS_INVALID_04: a conformant DUT in SYN-SENT silently
// drops a bare RST (RFC 793 §3.9). kTcpSynthRstOnDisruptive makes the lwIP netif input hook
// synthesize the prohibited RST on the connection's 4-tuple when the bare RST arrives (the
// disruptive-flag gate fires on the RST flag), and the case passes only when that synthesized
// RST is observed. lwIP-only (kCapIngressFault). A §4.8 must-not-respond case the
// ingress-synthesis seam reaches but the egress field-fault cannot — the conformant DUT emits
// nothing, so there is no DUT segment whose field a corruption could flip.
template <>
struct TestCaseTraits<cases::TcpFlagsInvalid04NegSM>
    : TcpIngressFaultNegBase<cases::TcpFlagsInvalid04NegSM> {
    static constexpr std::string_view kCaseId       = "TCP_FLAGS_INVALID_04_NEG";
    static constexpr std::string_view kSpecSection  = "4.8.6.6";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_FLAGS_INVALID_04: the lwIP kTcpSynthRstOnDisruptive ingress "
        "flavor makes the DUT emit a RST to a bare RST in SYN-SENT; a conformant DUT stays silent";

    // Mirrors the positive's prelude (TesterAutoRstDrop + seam SYN-SENT open + ISN_d learn +
    // bare-RST inject), with the fault armed between the DUT-SYN observation and the inject so
    // only the bare RST elicits the synthesized response. The synthesized RST carries seq=0 and
    // the 4-tuple swapped from the trigger; the case guard checks the 4-tuple + RST flag only.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        TesterAutoRstDrop rst_drop(cfg);
        (void)rst_drop;

        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 21U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 21U;

        auto snippet = TcpFrameSnippet::forDutSyn(cfg, iface, local_port);

        // Active OPEN routed through the backend-agnostic seam, no tester listener — the SYN
        // goes unanswered so the DUT stays in SYN-SENT, the state this case injects the bare
        // RST into. The handle is discarded (closing a SYN-SENT socket would abort the state).
        (void)driveSeamSynSentOpen(dut, cfg, local_port, remote_port);

        const auto syn = snippet.tryCapture(std::chrono::milliseconds(500));
        if (!syn.has_value()) return;

        // Per-phase arm: the DUT SYN has been observed (the SCXML precondition); arm so the
        // synthesis fires on the bare RST injected next. The eliciting inject carries the
        // arm settle so the raw-injected arm reaches the DUT UT thread first.
        emitIngressFlavorArmMidStream(cfg, iface, ::tc8::ut::kTcpSynthRstOnDisruptive);

        ::tc8::stimulus::TcpSegmentSpec bad{};
        bad.src_port = remote_port;
        bad.dst_port = local_port;
        bad.seq_num  = syn->seq_num + 1U;
        bad.ack_num  = 0U;
        bad.flags    = ::tc8::stimulus::kTcpFlagRst;
        emitTcpFrame(cfg, iface, cfg.dut.mac, bad,
                     /*initial_wait=*/kFlavorArmSettle);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsInvalid04NegSM, tcp_flags_invalid_04_neg)
