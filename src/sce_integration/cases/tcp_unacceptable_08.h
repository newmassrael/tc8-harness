#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_unacceptable_08_sm.h"

namespace tc8::sce::cases {

using TcpUnacceptable08SM = ::SCE::Generated::tcp_unacceptable_08::tcp_unacceptable_08;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpUnacceptable08SM>
    : TcpAnyBase<cases::TcpUnacceptable08SM> {
    static constexpr std::string_view kCaseId       = "TCP_UNACCEPTABLE_08";
    static constexpr std::string_view kDescription  =
        "TCP in SYN-SENT state MUST send a RST control message after "
        "receiving a segment with an unacceptable ACK number "
        "(RFC 793 §3.4 p36 Establishing a Connection)";

    // Each phase leaves the DUT's active open in SYN-SENT (no tester listener)
    // and injects the unacceptable-ACK segment into that state. The testability
    // CONNECT SP requires the handshake to establish and so cannot hold a
    // socket in SYN-SENT, while the opcode non-blocking worker can —
    // kCapTcpSynSentOpen makes the CLI capability gate honestly SKIP this case
    // on a testability backend (Tier 2 2b#4) instead of failing it. The DUT RST
    // is observed on pcap, so no state probe is required.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl | ::tc8::sce::kCapTcpSynSentOpen;

    // Spec Test Procedure (v3.0 p301-p320.txt:506), two iterations,
    // both exercised:
    //   * Phase 1 — CASE 1, flag set = SYN,ACK + unacceptable ACK.
    //   * Phase 2 — CASE 2, flag set = ACK + unacceptable ACK.
    //
    // Each phase runs the same active-OPEN → SYN learn → bad inject →
    // RST observation dance on a distinct port quad and socket_id
    // (mirror of FLAGS_INVALID_05). Phase 1 fires synchronously;
    // phase 2 schedules via scheduleAfterStateEntry(Listening_p2_dut_rst)
    // so its DUT SYN does not contend with phase 1's wall-clock
    // absence.
    //
    // Audit (claudedocs/false_positive_audit_2026_05_07.md) flagged
    // the historical CASE-2 omission as a TEST-DESIGN race against
    // tc8-dut's close-path connector-thread join. If the race
    // re-surfaces against a stock Linux DUT here, the case lands
    // fail_p2_no_dut_rst and is excluded from CI green via grep
    // filter in .github/workflows/smoke-test.yml. A spec-compliant
    // DUT without that race lands pass without filter.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut,
                         IStimulusScheduler& scheduler) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        runPhaseSynSentRst(
            dut, cfg, iface,
            /*local_port=*/kBasicsActiveLocalPort,
            /*remote_port=*/kBasicsActiveRemotePort,
            /*bad_inject_flags=*/static_cast<std::uint8_t>(
                ::tc8::stimulus::kTcpFlagSyn | ::tc8::stimulus::kTcpFlagAck));

        // Phase 2 runs in a deferred scheduler callback that outlives this
        // stimulus frame; capture the DUT control by pointer (CLI-owned, lives
        // past the callback) per the deferred-lambda idiom.
        ::tc8::sce::IDutControl* dut_ptr = &dut;
        ::tc8::TestConfig cfg_copy = cfg;
        std::string       iface_str(iface);
        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_p2_dut_rst),
            [dut_ptr, cfg_copy, iface_str]() {
                using namespace ::tc8::sce::tcp;
                runPhaseSynSentRst(
                    *dut_ptr, cfg_copy, iface_str,
                    /*local_port=*/static_cast<std::uint16_t>(kBasicsActiveLocalPort + 28U),
                    /*remote_port=*/static_cast<std::uint16_t>(kBasicsActiveRemotePort + 28U),
                    /*bad_inject_flags=*/::tc8::stimulus::kTcpFlagAck);
            });
    }

private:
    static void runPhaseSynSentRst(::tc8::sce::IDutControl& dut,
                                   const ::tc8::TestConfig& cfg,
                                   std::string_view iface,
                                   std::uint16_t local_port,
                                   std::uint16_t remote_port,
                                   std::uint8_t  bad_inject_flags) {
        using namespace ::tc8::sce::tcp;

        TesterAutoRstDrop rst_drop(cfg);
        (void)rst_drop;

        auto snippet = TcpFrameSnippet::forDutSyn(cfg, iface, local_port);

        // Seam active OPEN, no tester listener: the SYN stays unanswered so the
        // DUT remains in SYN-SENT, the state the unacceptable-ACK segment is
        // injected into.
        auto open = driveSeamSynSentOpen(dut, cfg, local_port, remote_port);

        const auto syn = snippet.tryCapture(std::chrono::milliseconds(500));
        if (syn.has_value()) {
            ::tc8::stimulus::TcpSegmentSpec bad{};
            bad.src_port = remote_port;
            bad.dst_port = local_port;
            bad.seq_num  = kTesterInitialSeq;
            bad.ack_num  = syn->seq_num + kUnacceptableAckOffset;
            bad.flags    = bad_inject_flags;
            emitTcpFrame(cfg, iface, cfg.dut.mac, bad,
                         /*initial_wait=*/std::chrono::milliseconds(0));
            std::this_thread::sleep_for(kTcpPilotPhaseGap);
        }

        if (open) dut.tcpControl()->closeTcp(open->socket);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpUnacceptable08SM, tcp_unacceptable_08)
