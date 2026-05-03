#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <unistd.h>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
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
    // §3.9 p70 and emits a duplicate ACK as the unacceptable-segment
    // response.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        auto listener = driveActiveOpenEstablished(
            cfg, iface, cfg.arp.dut_real_mac);

        const int tester_fd = listener.acceptOne();
        if (tester_fd >= 0) {
            const auto seq_range = queryTcpSeqRange(tester_fd);
            if (seq_range.has_value()) {
                ::tc8::stimulus::TcpSegmentSpec syn{};
                syn.src_port = kBasicsActiveRemotePort;
                syn.dst_port = kBasicsActiveLocalPort;
                // SEQ far above snd_nxt + maximum plausible window
                // scale (Linux default ~64 KB × 2^14 wscale ≈ 1 GB
                // ceiling). 16 MB offset is safely OTW for any
                // realistic window.
                syn.seq_num  = seq_range->snd_nxt + kOutOfWindowSeqOffset;
                syn.ack_num  = seq_range->rcv_nxt;
                syn.flags    = ::tc8::stimulus::kTcpFlagSyn;
                emitTcpFrame(cfg, iface, cfg.arp.dut_real_mac, syn,
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

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                       return "pass";
            case State::Fail_no_handshake_ack:      return "fail:no_dut_handshake_ack_within_listen_window";
            case State::Fail_no_otw_syn_ack:        return "fail:no_dut_ack_to_otw_syn";
            default:                                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpUnacceptable06SM, tcp_unacceptable_06)
