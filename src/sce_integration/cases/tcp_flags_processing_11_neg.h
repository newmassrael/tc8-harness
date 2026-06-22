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

#include "tcp_flags_processing_11_neg_sm.h"

namespace tc8::sce::cases {

using TcpFlagsProcessing11NegSM =
    ::SCE::Generated::tcp_flags_processing_11_neg::tcp_flags_processing_11_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.8.6.7 TCP_FLAGS_PROCESSING_11: a conformant DUT in ESTABLISHED
// silently ignores a duplicate ACK (RFC 793 §3.9). The duplicate ACK is itself a pure ACK, so
// the existing kTcpSynthRst flavor (pure-ACK gate -> synthesize RST) covers it with no new
// flavor: the lwIP netif input hook synthesizes the prohibited RST on the connection's 4-tuple
// when the duplicate ACK arrives, and the case passes only when a DUT segment is observed on
// that 4-tuple. lwIP-only (kCapIngressFault). The ingress-synthesis sibling of the positive's
// silence guard — a §4.8 must-not-respond case the egress field-fault cannot reach (the
// conformant DUT emits nothing).
template <>
struct TestCaseTraits<cases::TcpFlagsProcessing11NegSM>
    : TcpIngressFaultNegBase<cases::TcpFlagsProcessing11NegSM> {
    static constexpr std::string_view kCaseId       = "TCP_FLAGS_PROCESSING_11_NEG";
    static constexpr std::string_view kSpecSection  = "4.8.6.7";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_FLAGS_PROCESSING_11: the lwIP kTcpSynthRst ingress flavor makes "
        "the DUT emit a RST to a duplicate ACK in ESTABLISHED; a conformant DUT stays silent";

    // Mirrors the positive's prelude (active-OPEN to ESTABLISHED + tester seq snapshot +
    // duplicate-ACK inject), with the fault armed after the handshake so only the duplicate ACK
    // elicits the synthesized RST (the handshake SYN,ACK is not a pure ACK and the DUT third-leg
    // ACK is egress, both excluded by the pure-ACK gate). The _neg reads the wire for the
    // ESTABLISHED precondition, so it needs no kCapTcpStateProbe ut_established read.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        constexpr std::uint16_t kPortOffset = 50U;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kPortOffset;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kPortOffset;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0 || !open.conn) return;

        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (!seq_range.has_value()) return;

        // Per-phase arm: the handshake has completed, so the synthesis fires only on the
        // duplicate ACK injected next. The eliciting inject carries the arm settle so the
        // raw-injected arm reaches the DUT UT thread first.
        emitIngressFlavorArmMidStream(cfg, iface, ::tc8::ut::kTcpSynthRst);

        ::tc8::stimulus::TcpSegmentSpec dup_ack{};
        dup_ack.src_port = remote_port;
        dup_ack.dst_port = local_port;
        dup_ack.seq_num  = seq_range->snd_nxt;
        dup_ack.ack_num  = seq_range->rcv_nxt;
        dup_ack.flags    = ::tc8::stimulus::kTcpFlagAck;
        emitTcpFrame(cfg, iface, cfg.dut.mac, dup_ack,
                     /*initial_wait=*/kFlavorArmSettle);
        (void)tester_fd;
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsProcessing11NegSM, tcp_flags_processing_11_neg)
