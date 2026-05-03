#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <unistd.h>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_probing_windows_04_sm.h"

namespace tc8::sce::cases {

using TcpProbingWindows04SM =
    ::SCE::Generated::tcp_probing_windows_04::tcp_probing_windows_04;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpProbingWindows04SM>
    : TcpAnyBase<cases::TcpProbingWindows04SM> {
    static constexpr std::string_view kCaseId       = "TCP_PROBING_WINDOWS_04";
    static constexpr std::string_view kSpecSection  = "4.8.6.12";
    static constexpr std::string_view kDescription  =
        "DUT TCP MUST keep the connection open and emit zero-window "
        "probes indefinitely as long as the tester acknowledges each "
        "probe (RFC 1122 §4.2.2.17 — RFC 793 §3.7).";

    static constexpr std::array<std::uint8_t, 8> kSeg1Payload = {
        'P','4','S','1','d','a','t','a'};

    static constexpr std::array<std::uint8_t, 8> kSeg2Payload = {
        'P','4','S','2','d','a','t','a'};

    static constexpr std::chrono::milliseconds kPostSendSettle{150};
    static constexpr std::chrono::milliseconds kPostInjectSettle{150};

    // Hold-window for the deferred TesterAutoAckDrop release. The
    // 3-probe sequence may take up to ~10 s wall time on a slow
    // path (Linux's persist intervals double after each probe — RTO,
    // 2*RTO, 4*RTO with TCP_RTO_MIN=200 ms baseline). 12 s covers
    // the maximum plausible probe-3 fire time plus margin.
    static constexpr std::chrono::milliseconds kAckDropHold{12000};

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  =
            kBasicsActiveLocalPort  + kTcpProbingWindows04LocalOffset;
        const std::uint16_t remote_port =
            kBasicsActiveRemotePort + kTcpProbingWindows04LocalOffset;

        auto listener = driveActiveOpenEstablished(
            cfg, iface, cfg.arp.dut_real_mac,
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

        c.expected_ack_num = snd_una_post_ack - 1U;

        auto ack_drop = std::make_shared<TesterAutoAckDrop>(cfg);

        sendSendTcpDataRequest(
            cfg, iface, cfg.arp.dut_real_mac,
            /*req_id=*/2, /*socket_id=*/1,
            kSeg1Payload.data(),
            static_cast<std::uint16_t>(kSeg1Payload.size()));
        std::this_thread::sleep_for(kPostSendSettle);

        // Spec step 4: tester ACKs seg1 with `window=0`.
        {
            ::tc8::stimulus::TcpSegmentSpec ack_seg{};
            ack_seg.src_port = remote_port;
            ack_seg.dst_port = local_port;
            ack_seg.seq_num  = tester_snd;
            ack_seg.ack_num  = snd_una_post_ack;
            ack_seg.flags    = ::tc8::stimulus::kTcpFlagAck;
            ack_seg.window   = 0U;
            emitTcpFrame(cfg, iface, cfg.arp.dut_real_mac, ack_seg,
                         /*initial_wait=*/std::chrono::milliseconds(0));
        }
        std::this_thread::sleep_for(kPostInjectSettle);

        // Spec step 5: SEND 2 — bytes queue behind snd_wnd=0.
        sendSendTcpDataRequest(
            cfg, iface, cfg.arp.dut_real_mac,
            /*req_id=*/3, /*socket_id=*/1,
            kSeg2Payload.data(),
            static_cast<std::uint16_t>(kSeg2Payload.size()));

        // Spec step 7: acknowledge each probe maintaining zero
        // window. State-entry observers fire their lambda when SCXML
        // transitions INTO the target state — i.e. immediately after
        // the corresponding probe has been observed and the SM has
        // settled on the next listening_probe* state.
        //
        // Observer for Listening_probe2 fires after probe 1 lands;
        // its lambda raw-injects ACK_after_probe1 (same ack_num,
        // window=0). Linux's `tcp_ack_probe` reschedules the next
        // probe with current `icsk_backoff` (no reset because
        // snd_una does not advance), and probe 2 fires after the
        // doubled interval. Same shape for Listening_probe3.
        const auto dut_mac = cfg.arp.dut_real_mac;
        const std::string iface_str(iface);
        const auto inject_zero_window_ack =
            [cfg, iface_str, dut_mac, local_port, remote_port,
             tester_snd, snd_una_post_ack, ack_drop]() {
                ::tc8::stimulus::TcpSegmentSpec ack_seg{};
                ack_seg.src_port = remote_port;
                ack_seg.dst_port = local_port;
                ack_seg.seq_num  = tester_snd;
                ack_seg.ack_num  = snd_una_post_ack;
                ack_seg.flags    = ::tc8::stimulus::kTcpFlagAck;
                ack_seg.window   = 0U;
                ::tc8::sce::tcp::emitTcpFrame(
                    cfg, iface_str, dut_mac, ack_seg,
                    /*initial_wait=*/std::chrono::milliseconds(0));
                (void)ack_drop;
            };

        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_probe2),
            inject_zero_window_ack);
        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_probe3),
            inject_zero_window_ack);

        // Backstop holder so ack_drop survives the full probe
        // sequence even if state-entry observers have already fired
        // and dropped their captures.
        scheduler.schedule(kAckDropHold, [ack_drop]() {
            (void)ack_drop;
        });

        (void)tester_fd;
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                                       return "pass";
            case State::Fail_no_seg1:                               return "fail:no_dut_first_data_segment";
            case State::Fail_no_probe1:                             return "fail:no_dut_zero_window_probe_1";
            case State::Fail_no_probe2:                             return "fail:no_dut_zero_window_probe_2_after_ack";
            case State::Fail_no_probe3:                             return "fail:no_dut_zero_window_probe_3_after_ack";
            default:                                                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpProbingWindows04SM, tcp_probing_windows_04)
