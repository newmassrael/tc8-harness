#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <unistd.h>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_unacceptable_06_sm.h"

namespace tc8::sce::cases {

using TcpUnacceptable06SM = ::SCE::Generated::tcp_unacceptable_06::tcp_unacceptable_06;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpUnacceptable06SM>
    : TcpAnyBase<cases::TcpUnacceptable06SM> {
    static constexpr std::string_view kCaseId       = "TCP_UNACCEPTABLE_06";
    static constexpr std::string_view kSpecSection  = "4.8.6.3";
    static constexpr std::string_view kDescription  =
        "TCP in ESTABLISHED state MUST send an ACK indicating the "
        "correct SEQ number it expects, after receiving a SYN with a "
        "SEQ number out of window (RFC 793 §3.4 p34 Establishing a "
        "Connection)";

    // Spec Test Procedure (v3.0 p301-p320.txt:440):
    //   1. TESTER: Cause DUT to ESTABLISHED.
    //   2. TESTER: Send SYN with SEQ outside the receive window.
    //   3. DUT:    Send ACK indicating expected SEQ.
    //
    // After active-OPEN ESTABLISHED, queryTcpSeqRange snapshots
    // tester's snd_nxt / rcv_nxt; the OTW SYN places SEQ far past
    // snd_nxt + window so the DUT discards the segment per RFC 793
    // RFC 793 §3.9 p70 and emits a duplicate ACK as the unacceptable-segment
    // response.
    //
    // Spec literal (TC8 v3.0 p442 Pass Criteria step 3):
    //   "DUT: Send an ACK indicating next expected SEQ number."
    // The "next expected SEQ number" the DUT acks back equals the
    // tester's snd_nxt at corrupt-segment receipt time — the OTW
    // segment was discarded, so DUT's rcv_nxt is unchanged from
    // the snapshot. expected_ack_num = seq_range->snd_nxt is the
    // SCXML-side strict-pass conjunct value.
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        auto open = driveSeamActiveOpen(
            dut, cfg,
            kBasicsActiveLocalPort  + kTcpUnacceptable06LocalOffset,
            kBasicsActiveRemotePort + kTcpUnacceptable06LocalOffset);

        const int tester_fd = open.listener.acceptOne();
        if (tester_fd >= 0) {
            const auto seq_range = queryTcpSeqRange(tester_fd);
            if (seq_range.has_value()) {
                c.expected_ack_num = seq_range->snd_nxt;
                ::tc8::stimulus::TcpSegmentSpec syn{};
                syn.src_port = kBasicsActiveRemotePort + kTcpUnacceptable06LocalOffset;
                syn.dst_port = kBasicsActiveLocalPort  + kTcpUnacceptable06LocalOffset;
                // SEQ far above snd_nxt + maximum plausible window
                // scale (Linux default ~64 KB × 2^14 wscale ≈ 1 GB
                // ceiling). 16 MB offset is safely OTW for any
                // realistic window.
                syn.seq_num  = seq_range->snd_nxt + kOutOfWindowSeqOffset;
                syn.ack_num  = seq_range->rcv_nxt;
                syn.flags    = ::tc8::stimulus::kTcpFlagSyn;
                emitTcpFrame(cfg, iface, cfg.dut.mac, syn,
                             /*initial_wait=*/std::chrono::milliseconds(0));
            }
            // Connection cleanup deferred to process exit (same
            // rationale as CHECKSUM_02): a close-driven FIN exchange
            // here would generate DUT-origin pure-ACK segments that
            // contaminate the post-stimulus listen window. The
            // tc8-dut's accepted_fd is closed by smoke-test's
            // SIGKILL after the harness pcap source has been torn
            // down.
            (void)tester_fd;
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpUnacceptable06SM, tcp_unacceptable_06)
