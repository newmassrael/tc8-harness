#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <vector>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam_active_open.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_mss_options_09_sm.h"

namespace tc8::sce::cases {

using TcpMssOptions09SM = ::SCE::Generated::tcp_mss_options_09::tcp_mss_options_09;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpMssOptions09SM>
    : TcpAnyBase<cases::TcpMssOptions09SM> {
    static constexpr std::string_view kCaseId       = "TCP_MSS_OPTIONS_09";
    static constexpr std::string_view kSpecSection  = "4.8.6.9";
    static constexpr std::string_view kDescription  =
        "DUT MUST receive an MSS option in a SYN,ACK segment and "
        "clamp the effective send segment size to min(advertised, "
        "DUT_MSS) (RFC 1122 §4.2.2.5 p85). Iterations: Mv=200 "
        "(smaller), Mv=2000 (larger).";

    // Each iteration holds the DUT's active open in SYN-SENT (no tester
    // listener) until the crafted SYN+ACK injection establishes it. The
    // testability CONNECT SP requires the handshake to establish and so cannot
    // hold a socket in SYN-SENT, while the opcode non-blocking worker can —
    // kCapTcpSynSentOpen makes the CLI capability gate honestly SKIP this case
    // on a testability backend (Tier 2 2b#4) instead of failing it. The DUT
    // third-leg ACK and the clamped data segments are observed on pcap, so no
    // state probe is required.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl | ::tc8::sce::kCapTcpSynSentOpen;

    // Drive one iteration: SYN-SENT active OPEN, capture DUT SYN, raw-inject
    // SYN+ACK with kind=2 length=4 MSS=Mv, bulk-send (DUT emits 4000 B), close.
    // The outer TesterAutoRstDrop scope (in stimulus()) covers the whole flow —
    // the SYN-SENT period and the post-handshake data flow on the 4-tuple the
    // tester never accepted.
    static void runPhase(::tc8::sce::IDutControl& dut,
                         const ::tc8::TestConfig &cfg,
                         std::string_view iface,
                         const std::array<std::uint8_t, 6> &dut_mac,
                         std::uint16_t port_offset,
                         std::uint16_t advertised_mss) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  =
            static_cast<std::uint16_t>(kBasicsActiveLocalPort  + port_offset);
        const std::uint16_t remote_port =
            static_cast<std::uint16_t>(kBasicsActiveRemotePort + port_offset);

        auto snippet = TcpFrameSnippet::forDutSyn(cfg, iface, local_port);

        // Seam active OPEN, no tester listener: the SYN stays unanswered so the
        // DUT remains in SYN-SENT until the crafted SYN+ACK injection below.
        auto open = driveSeamSynSentOpen(dut, cfg, local_port, remote_port);

        const auto syn = snippet.tryCapture(std::chrono::milliseconds(1000));
        if (syn.has_value()) {
            // RFC 793 §3.1 kind=2 length=4 MSS option, BE 16-bit value.
            const std::vector<std::uint8_t> mss_option{
                0x02U, 0x04U,
                static_cast<std::uint8_t>((advertised_mss >> 8) & 0xFFU),
                static_cast<std::uint8_t>(advertised_mss & 0xFFU)};

            ::tc8::stimulus::TcpSegmentSpec synack{};
            synack.src_port = remote_port;
            synack.dst_port = local_port;
            synack.seq_num  = kTesterInitialSeq;
            synack.ack_num  = syn->seq_num + 1U;
            synack.flags    = ::tc8::stimulus::kTcpFlagSyn
                            | ::tc8::stimulus::kTcpFlagAck;
            synack.options  = mss_option;
            emitTcpFrame(cfg, iface, dut_mac, synack,
                         /*initial_wait=*/std::chrono::milliseconds(0));

            // 200 ms covers SYN+ACK landing → DUT third-leg ACK egress
            // → tc8-dut connect() unblock → accepted_fd assignment.
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }

        if (open) {
            // 4000 B > 2 × 1460 ensures Linux segments at least twice on
            // the larger-Mv path; the first segment carries min(Mv, 1460).
            seamSendTcpPattern(dut, open->socket, /*pattern=*/0xC3U,
                               /*total_len=*/4000U);
            std::this_thread::sleep_for(std::chrono::milliseconds(200));

            dut.tcpControl()->closeTcp(open->socket);
        }
        std::this_thread::sleep_for(kTcpUtRpcWait);
    }

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        // RstDrop scope covers SYN-SENT (no tester listener) plus the
        // post-handshake data flow (orphaned 4-tuple from tester's
        // perspective).
        TesterAutoRstDrop rst_drop(cfg);
        (void)rst_drop;

        // Phase 1: Mv=200 < DUT MSS=1460. Expected first DUT segment
        // size = 200.
        runPhase(dut, cfg, iface, cfg.dut.mac,
                 kTcpMssOptions09Phase1LocalOffset,
                 /*advertised_mss=*/200U);

        // Phase 2: Mv=2000 > DUT MSS. Expected first segment clamped
        // to DUT MSS = 1460.
        runPhase(dut, cfg, iface, cfg.dut.mac,
                 kTcpMssOptions09Phase2LocalOffset,
                 /*advertised_mss=*/2000U);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                       return "pass";
            case State::Fail_wrong_size_phase1:     return "fail:phase1_segment_size_not_advertised_mss_200";
            case State::Fail_wrong_size_phase2:     return "fail:phase2_segment_size_not_dut_mss_1460";
            case State::Fail_timeout_phase1:        return "fail:no_dut_data_segment_phase1_mv200";
            case State::Fail_timeout_phase2:        return "fail:no_dut_data_segment_phase2_mv2000";
            default:                                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpMssOptions09SM, tcp_mss_options_09)
