#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string_view>
#include <thread>
#include <unistd.h>
#include <variant>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/stimulus_observation.h"
#include "sce_integration/tcp_observation.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_probing_windows_05_sm.h"

namespace tc8::sce::cases {

using TcpProbingWindows05SM =
    ::SCE::Generated::tcp_probing_windows_05::tcp_probing_windows_05;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpProbingWindows05SM>
    : TcpDutDrivenBase<cases::TcpProbingWindows05SM> {
    static constexpr std::string_view kCaseId       = "TCP_PROBING_WINDOWS_05";
    static constexpr std::string_view kDescription  =
        "DUT TCP SHOULD send the first zero-window probe after the "
        "retransmission timeout when the receive window remains zero "
        "(RFC 1122 §4.2.2.17 — RFC 793 §3.7).";

    // Distinct first byte aids pcap visual inspection; payload size
    // is well under upper_tester_protocol.h kMaxPayload (256 B) and
    // far below MSS so Nagle is irrelevant — we only need a single
    // segment to land on the wire so the receiver can ACK with
    // window=0 and trigger persist mode for the second SEND.
    static constexpr std::array<std::uint8_t, 8> kSeg1Payload = {
        'P','5','S','1','d','a','t','a'};

    // Second SEND payload — Linux enqueues these bytes after the
    // window=0 ACK has shrunk snd_wnd to 0. They never leave the
    // wire until a window update arrives; their role is to put the
    // socket into persist mode so the probe timer fires.
    static constexpr std::array<std::uint8_t, 8> kSeg2Payload = {
        'P','5','S','2','d','a','t','a'};

    // How long the stimulus waits for seg1, and for the tester's own
    // zero-window ACK to show in the capture (it is on the wire once
    // emitted, so this only covers capture latency).
    static constexpr std::chrono::milliseconds kSeg1Bound{5000};
    static constexpr std::chrono::milliseconds kOwnFrameBound{1000};

    // Settle wait between window=0 inject and second SEND so the
    // DUT's tcp_ack_update_window has fired (snd_wnd=0, persist
    // timer started) before the second SEND enqueues new data.
    static constexpr std::chrono::milliseconds kPostInjectSettle{150};

    // Hold-window for the deferred TesterAutoAckDrop release. The
    // CLI runs `kickStimulus` synchronously before runner->start()
    // and the dispatch loop, so an ack_drop scoped to the stimulus
    // body would die at stimulus return — i.e. before the SCXML
    // listen window opens. Without ongoing ACK suppression the
    // tester kernel's auto-ACK to seg1 would race ahead of the
    // harness's window=0 ACK with full window, the DUT's snd_wnd
    // would never collapse to zero, and the probe path would not
    // be exercised. 12 s outlasts the 11 s probe phase deadline, which
    // opens as the listen window does.
    static constexpr std::chrono::milliseconds kAckDropHold{12000};

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        using namespace ::tc8::sce::tcp;

        const std::uint16_t local_port  =
            kBasicsActiveLocalPort  + kTcpProbingWindows05LocalOffset;
        const std::uint16_t remote_port =
            kBasicsActiveRemotePort + kTcpProbingWindows05LocalOffset;

        auto open = driveSeamActiveOpen(ctx.dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0 || !open.conn) return;

        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (!seq_range.has_value()) {
            ::close(tester_fd);
            return;
        }

        const std::uint32_t seg1_seq = seq_range->rcv_nxt;
        const std::uint32_t snd_una_post_ack =
            seg1_seq + static_cast<std::uint32_t>(kSeg1Payload.size());
        const std::uint32_t tester_snd  = seq_range->snd_nxt;

        // Probe seq per Linux's tcp_xmit_probe_skb(urgent=0):
        //   seq = snd_una - !urgent = snd_una - 1
        c.expected_ack_num = snd_una_post_ack - 1U;

        auto ack_drop = std::make_shared<TesterAutoAckDrop>(cfg);

        // Spec step 2/3: SEND 1 → DUT seg1.
        const std::uint32_t seg1_len = static_cast<std::uint32_t>(kSeg1Payload.size());
        const ::tc8::sce::ObservationCursor first_send = ctx.observer.mark();
        seamSendTcp(ctx.dut, open.conn->socket, kSeg1Payload);
        const auto seg1 = ctx.observer.awaitObservation(
            "dut_first_data_segment", first_send,
            dutDataSegmentAt(cfg.dut.ip, local_port, seg1_seq, seg1_len), kSeg1Bound);
        if (!seg1) return;
        const std::int64_t seg1_ts = segmentOf(seg1->view()).observed_ts_us;

        // Step 7 grades the probe against "the retransmission timeout", which is
        // the DUT's own. The tester learns it the only way the wire shows it:
        // seg1 stays unacknowledged until the DUT retransmits it, and the gap is
        // the DUT's timeout on this connection. The DUT is granted
        // ParamListenTime to retransmit; a timeout longer than that leaves the
        // probe's bound unknown, so the case is inconclusive (recorded below).
        const auto retransmission = ctx.observer.awaitObservation(
            "dut_first_data_segment_retransmission", first_send,
            dutDataSegmentAt(cfg.dut.ip, local_port, seg1_seq, seg1_len, seg1_ts),
            std::chrono::milliseconds(cfg.ixit.param_listen_time_ms));
        if (!retransmission) return;
        c.dut_rto_us = segmentOf(retransmission->view()).observed_ts_us - seg1_ts;

        // Spec step 4: tester ACKs seg1 with `window=0`. snd_una
        // advances to seg1_seq + |seg1|; snd_wnd = 0. The zero window
        // begins when this ACK is on the wire, so its capture time is
        // what the probe's wait is measured from.
        {
            ::tc8::stimulus::TcpSegmentSpec ack_seg{};
            ack_seg.src_port = remote_port;
            ack_seg.dst_port = local_port;
            ack_seg.seq_num  = tester_snd;
            ack_seg.ack_num  = snd_una_post_ack;
            ack_seg.flags    = ::tc8::stimulus::kTcpFlagAck;
            ack_seg.window   = 0U;
            const ::tc8::sce::ObservationCursor before_ack = ctx.observer.mark();
            emitTcpFrame(cfg, ctx.iface, cfg.dut.mac, ack_seg,
                         /*initial_wait=*/std::chrono::milliseconds(0));
            // Keyed on the tester's own address, its identity, not on the DUT
            // address the frame is sent to, which negative rows flip.
            const std::uint32_t tester_ip = cfg.tester.ip;
            const auto zero_window_ack = ctx.observer.awaitObservation(
                "tester_zero_window_ack", before_ack,
                [tester_ip, local_port, remote_port, snd_una_post_ack](const ::tc8::CapturedEvent &ev) {
                    const auto *t = std::get_if<::tc8::TcpFrame>(&ev);
                    return t != nullptr && t->src_ip == tester_ip && t->dst_port == local_port &&
                           t->src_port == remote_port && t->flags == ::tc8::stimulus::kTcpFlagAck &&
                           t->window == 0U && t->ack_num == snd_una_post_ack;
                },
                kOwnFrameBound);
            if (!zero_window_ack) return;
            c.zero_window_since_ts_us = segmentOf(zero_window_ack->view()).observed_ts_us;
        }
        std::this_thread::sleep_for(kPostInjectSettle);

        // Spec step 5: SEND 2 — bytes queue behind snd_wnd=0; the
        // socket is now in persist state, awaiting the probe timer.
        seamSendTcp(ctx.dut, open.conn->socket, kSeg2Payload);

        // Defer ack_drop release to the runner's scheduler so the
        // iptables OUTPUT rule remains installed across the SCXML
        // listen window — see kAckDropHold comment.
        ctx.scheduler.schedule(kAckDropHold, [ack_drop]() {
            (void)ack_drop;
        });

        (void)tester_fd;
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpProbingWindows05SM, tcp_probing_windows_05)
