#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <string_view>
#include <thread>
#include <unistd.h>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam_active_open.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_probing_windows_03_sm.h"

namespace tc8::sce::cases {

using TcpProbingWindows03SM =
    ::SCE::Generated::tcp_probing_windows_03::tcp_probing_windows_03;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpProbingWindows03SM>
    : TcpAnyBase<cases::TcpProbingWindows03SM> {
    static constexpr std::string_view kCaseId       = "TCP_PROBING_WINDOWS_03";
    static constexpr std::string_view kSpecSection  = "4.8.6.12";
    static constexpr std::string_view kDescription  =
        "DUT TCP MUST be robust against window shrinking — when the "
        "useable window becomes negative, the DUT must not transmit "
        "any data segment beyond the previously emitted range "
        "(RFC 1122 §4.2.2.16 — RFC 793 §3.7).";

    // Fallback full-MSS payload (1460 B on a 1500 B veth) used only
    // when the negotiated send MSS cannot be queried; the stimulus
    // prefers seq_range->mss (see seg_len below). Nagle's small-segment
    // hold does not apply to MSS-fill segments, so the three sequential
    // SENDs each ship out as their own data segment without requiring
    // TCP_NODELAY on the DUT-side socket.
    //
    // OpSendTcpData caps at upper_tester_protocol.h kMaxPayload (256 B)
    // because the bytes traverse the UT UDP request. For >256 B sends
    // the harness uses OpSendTcpDataPattern: the tc8-dut allocates
    // `total_len` bytes filled with `pattern` and writes them via
    // ::send() — Linux's TCP stack segments per the negotiated send
    // MSS without crossing the UT-UDP boundary. Same idiom NAGLE_03
    // uses for its 1450-byte aggregate-fill phase.
    static constexpr std::uint16_t kSegmentPayloadLen = 1460U;

    // Pattern bytes for each SEND — distinct first nibble aids pcap
    // visual inspection but is not load-bearing.
    static constexpr std::uint8_t kSeg1Pattern = 0xA1U;
    static constexpr std::uint8_t kSeg2Pattern = 0xA2U;
    static constexpr std::uint8_t kSeg3Pattern = 0xA3U;
    static constexpr std::uint8_t kSeg4Pattern = 0xA4U;

    // Settle between an injected ACK and the next UT SEND so the
    // DUT's tcp_ack_update_window has run before the application
    // send is enqueued. 150 ms covers softirq scheduling jitter
    // under parallel workers without bloating case wall-time.
    static constexpr std::chrono::milliseconds kPostInjectSettle{150};

    // Brief grace after each SEND so the DUT-side data segment lands
    // on the wire before the next stimulus step issues an ACK that
    // logically refers to the just-emitted segment.
    static constexpr std::chrono::milliseconds kPostSendSettle{150};

    // Hold-window for the deferred TesterAutoAckDrop release. The
    // CLI runs `kickStimulus` SYNCHRONOUSLY before `runner->start()`
    // and the dispatch loop, so a TesterAutoAckDrop scoped to the
    // stimulus body would die at stimulus return — i.e. BEFORE the
    // SCXML absence_no_seg4 window even opens (the SM only initializes
    // post-stimulus per `runner->start()` ordering). Without ongoing
    // ACK suppression the tester kernel's auto-ACK to a seg3 retransmit
    // arrives with full window, the DUT's snd_wnd re-opens, the
    // queued seg4 (and the un-emitted 12-byte tail of seg3) ship out,
    // and the absence guard fails on `seq_num > seg3_seq`.
    //
    // Solution: capture a `std::shared_ptr<TesterAutoAckDrop>` in a
    // `scheduler.schedule(...)` lambda; the runner's scheduler holds
    // the lambda (and the strong ref) for the configured delay,
    // keeping the iptables rule installed across the absence window.
    // 8 s comfortably exceeds the 4 s absence window plus dispatcher
    // backlog drain time on the slowest parallel-worker run observed.
    static constexpr std::chrono::milliseconds kAckDropHold{8000};

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut,
                         IStimulusScheduler& scheduler) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  =
            kBasicsActiveLocalPort  + kTcpProbingWindows03LocalOffset;
        const std::uint16_t remote_port =
            kBasicsActiveRemotePort + kTcpProbingWindows03LocalOffset;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        if (!open.conn) return;
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0) return;

        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (!seq_range.has_value()) {
            ::close(tester_fd);
            return;
        }

        // Stride the seq expectations by the DUT's negotiated send MSS
        // (1448 B for a timestamp-enabled stack like lwIP, 1460 B for
        // the timestamp-disabled Linux reference DUT) rather than a
        // fixed assumption — the prelude must land seg2/seg3 at the
        // DUT's real segment boundaries on any conformant stack. Each
        // SEND ships exactly one MSS so it leaves as a single full
        // segment (Nagle's small-segment hold never applies).
        const std::uint16_t seg_len =
            (seq_range->mss > 0U) ? seq_range->mss : kSegmentPayloadLen;

        // rcv_nxt at this point equals DUT_ISN + 1 — the seq_num the
        // DUT will assign to the first data segment (= S).
        const std::uint32_t seg1_seq = seq_range->rcv_nxt;
        const std::uint32_t seg2_seq = seg1_seq + seg_len;
        const std::uint32_t seg3_seq = seg2_seq + seg_len;
        const std::uint32_t tester_snd = seq_range->snd_nxt;

        c.expected_ack_num        = seg2_seq;
        c.expected_ack_num_phase2 = seg3_seq;

        // Suppress tester-kernel auto-ACKs so only the harness's
        // raw-injected ACKs reach the DUT. AF_PACKET injection
        // bypasses the iptables OUTPUT chain, so harness ACKs ride
        // through unaffected. shared_ptr so the strong ref can
        // outlive stimulus return — see kAckDropHold comment.
        auto ack_drop = std::make_shared<TesterAutoAckDrop>(cfg);

        // Spec step 2/3: SEND 1 → DUT seg1 at seq=S.
        seamSendTcpPattern(dut, open.conn->socket, kSeg1Pattern, seg_len);
        std::this_thread::sleep_for(kPostSendSettle);

        // Spec step 4: tester ACKs seg1 with full window. Linux's
        // tcp_ack_update_window accepts (ack > prior_snd_una) so
        // snd_una advances to S+MSS and snd_wnd takes the announced
        // value (full so seg2 / seg3 are admissible).
        {
            ::tc8::stimulus::TcpSegmentSpec ack_seg{};
            ack_seg.src_port = remote_port;
            ack_seg.dst_port = local_port;
            ack_seg.seq_num  = tester_snd;
            ack_seg.ack_num  = seg2_seq;
            ack_seg.flags    = ::tc8::stimulus::kTcpFlagAck;
            ack_seg.window   = 0xFFFFU;
            emitTcpFrame(cfg, iface, cfg.dut.mac, ack_seg,
                         /*initial_wait=*/std::chrono::milliseconds(0));
        }
        std::this_thread::sleep_for(kPostInjectSettle);

        // Spec step 5/6: SEND 2 + SEND 3 → DUT seg2 + seg3.
        seamSendTcpPattern(dut, open.conn->socket, kSeg2Pattern, seg_len);
        std::this_thread::sleep_for(kPostSendSettle);

        seamSendTcpPattern(dut, open.conn->socket, kSeg3Pattern, seg_len);
        std::this_thread::sleep_for(kPostSendSettle);

        // Spec step 7: tester ACKs seg2 only with `window=0` —
        // window-shrink. snd_una advances to S+2*MSS, snd_wnd=0;
        // snd_nxt remains S+3*MSS (seg3 still outstanding) so
        // usable_win = (S+2*MSS) + 0 - (S+3*MSS) = -MSS (negative).
        {
            ::tc8::stimulus::TcpSegmentSpec ack_seg{};
            ack_seg.src_port = remote_port;
            ack_seg.dst_port = local_port;
            ack_seg.seq_num  = tester_snd;
            ack_seg.ack_num  = seg3_seq;  // ACKs seg2 (= S+MSS .. S+2*MSS-1)
            ack_seg.flags    = ::tc8::stimulus::kTcpFlagAck;
            ack_seg.window   = 0U;
            emitTcpFrame(cfg, iface, cfg.dut.mac, ack_seg,
                         /*initial_wait=*/std::chrono::milliseconds(0));
        }
        std::this_thread::sleep_for(kPostInjectSettle);

        // Spec step 8: SEND 4 — DUT must NOT emit seg4 (any data
        // segment with seq >= S+3*MSS). Linux is in persist mode
        // (snd_wnd=0) and emits 0-byte zero-window probes only;
        // those carry payload_len==0 and are filtered out by the
        // SCXML `is_dut_data_segment` predicate (payload_len > 0
        // conjunct).
        seamSendTcpPattern(dut, open.conn->socket, kSeg4Pattern, seg_len);

        // Defer ack_drop release to the runner's scheduler — the
        // captured shared_ptr keeps the iptables OUTPUT rule
        // installed across the SCXML absence_no_seg4 window even
        // after the stimulus body returns.
        scheduler.schedule(kAckDropHold, [ack_drop]() {
            (void)ack_drop;
        });

        (void)tester_fd;
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                                       return "pass";
            case State::Fail_no_seg1:                               return "fail:no_dut_first_data_segment";
            case State::Fail_no_seg2:                               return "fail:no_dut_second_data_segment";
            case State::Fail_no_seg3:                               return "fail:no_dut_third_data_segment";
            case State::Fail_dut_sent_past_shrunk_window:           return "fail:dut_sent_segment_past_shrunk_window_negative_usable_window_violation";
            default:                                                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpProbingWindows03SM, tcp_probing_windows_03)
