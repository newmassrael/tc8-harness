#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string_view>
#include <thread>
#include <unistd.h>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
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
    : TcpAnyBase<cases::TcpProbingWindows05SM> {
    static constexpr std::string_view kCaseId       = "TCP_PROBING_WINDOWS_05";
    static constexpr std::string_view kSpecSection  = "4.8.6.12";
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

    // Settle wait between seg1 SEND and the window=0 ACK inject so
    // the kernel has flushed seg1 onto the wire before we ack it
    // (and so the SCXML observes seg1 before the SM may transition
    // to listening_probe via post-stimulus dispatch).
    static constexpr std::chrono::milliseconds kPostSendSettle{150};

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
    // be exercised. 8 s comfortably exceeds the 5 s seg1 phase
    // deadline plus the 6 s probe phase deadline less the typical
    // ~200 ms..1 s probe-firing latency on local veth.
    static constexpr std::chrono::milliseconds kAckDropHold{8000};

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  =
            kBasicsActiveLocalPort  + kTcpProbingWindows05LocalOffset;
        const std::uint16_t remote_port =
            kBasicsActiveRemotePort + kTcpProbingWindows05LocalOffset;

        auto listener = driveActiveOpenEstablished(
            cfg, iface, cfg.dut.mac,
            /*open_req_id=*/1, local_port, remote_port);
        const int tester_fd = listener.acceptOne();
        if (tester_fd < 0) return;

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
        sendSendTcpDataRequest(
            cfg, iface, cfg.dut.mac,
            /*req_id=*/2, /*socket_id=*/1,
            kSeg1Payload.data(),
            static_cast<std::uint16_t>(kSeg1Payload.size()));
        std::this_thread::sleep_for(kPostSendSettle);

        // Spec step 4: tester ACKs seg1 with `window=0`. snd_una
        // advances to seg1_seq + |seg1|; snd_wnd = 0. Linux enters
        // persist mode and arms the probe timer.
        {
            ::tc8::stimulus::TcpSegmentSpec ack_seg{};
            ack_seg.src_port = remote_port;
            ack_seg.dst_port = local_port;
            ack_seg.seq_num  = tester_snd;
            ack_seg.ack_num  = snd_una_post_ack;
            ack_seg.flags    = ::tc8::stimulus::kTcpFlagAck;
            ack_seg.window   = 0U;
            emitTcpFrame(cfg, iface, cfg.dut.mac, ack_seg,
                         /*initial_wait=*/std::chrono::milliseconds(0));
        }
        std::this_thread::sleep_for(kPostInjectSettle);

        // Spec step 5: SEND 2 — bytes queue behind snd_wnd=0; the
        // socket is now in persist state, awaiting the probe timer.
        sendSendTcpDataRequest(
            cfg, iface, cfg.dut.mac,
            /*req_id=*/3, /*socket_id=*/1,
            kSeg2Payload.data(),
            static_cast<std::uint16_t>(kSeg2Payload.size()));

        // Defer ack_drop release to the runner's scheduler so the
        // iptables OUTPUT rule remains installed across the SCXML
        // listen window — see kAckDropHold comment.
        scheduler.schedule(kAckDropHold, [ack_drop]() {
            (void)ack_drop;
        });

        (void)tester_fd;
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                                       return "pass";
            case State::Fail_no_seg1:                               return "fail:no_dut_first_data_segment";
            case State::Fail_no_zero_window_probe:                  return "fail:no_dut_zero_window_probe_within_rto_window";
            default:                                                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpProbingWindows05SM, tcp_probing_windows_05)
