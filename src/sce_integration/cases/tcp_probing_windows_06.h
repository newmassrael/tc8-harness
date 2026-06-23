#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string_view>
#include <thread>
#include <unistd.h>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_probing_windows_06_sm.h"

namespace tc8::sce::cases {

using TcpProbingWindows06SM =
    ::SCE::Generated::tcp_probing_windows_06::tcp_probing_windows_06;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpProbingWindows06SM>
    : TcpAnyBase<cases::TcpProbingWindows06SM> {
    static constexpr std::string_view kCaseId       = "TCP_PROBING_WINDOWS_06";
    static constexpr std::string_view kDescription  =
        "DUT TCP SHOULD increase exponentially the interval between "
        "successive zero-window probes (RFC 1122 §4.2.2.17 — RFC 793 "
        "§3.7).";

    static constexpr std::array<std::uint8_t, 8> kSeg1Payload = {
        'P','6','S','1','d','a','t','a'};

    static constexpr std::array<std::uint8_t, 8> kSeg2Payload = {
        'P','6','S','2','d','a','t','a'};

    static constexpr std::chrono::milliseconds kPostSendSettle{150};
    static constexpr std::chrono::milliseconds kPostInjectSettle{150};

    // Hold-window for the deferred TesterAutoAckDrop release. Linux's
    // unACKed exponential probe sequence reaches probe 3 within
    // ~2.2 s on a fresh local-veth connection (200 ms + 600 ms +
    // 1.4 s); 8 s covers the full SCXML probe-phase budget plus
    // margin.
    static constexpr std::chrono::milliseconds kAckDropHold{8000};

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut,
                         IStimulusScheduler& scheduler) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  =
            kBasicsActiveLocalPort  + kTcpProbingWindows06LocalOffset;
        const std::uint16_t remote_port =
            kBasicsActiveRemotePort + kTcpProbingWindows06LocalOffset;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
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

        c.expected_ack_num = snd_una_post_ack - 1U;

        auto ack_drop = std::make_shared<TesterAutoAckDrop>(cfg);

        seamSendTcp(dut, open.conn->socket, kSeg1Payload);
        std::this_thread::sleep_for(kPostSendSettle);

        // Spec step 4: window=0 ACK.
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

        // Spec step 5: SEND 2 — bytes queue behind snd_wnd=0.
        seamSendTcp(dut, open.conn->socket, kSeg2Payload);

        // No per-probe ACK injection — Linux's `icsk_backoff`
        // increments on each probe-fire, so successive probes ship
        // at exponentially-doubled intervals naturally. ACKing
        // each probe (which TCP_PROBING_WINDOWS_04 does) tests a
        // related but distinct property — the connection must
        // STAY OPEN across acked probes; backoff continues
        // unaffected (snd_una never advances, so backoff is not
        // reset).
        scheduler.schedule(kAckDropHold, [ack_drop]() {
            (void)ack_drop;
        });

        (void)tester_fd;
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpProbingWindows06SM, tcp_probing_windows_06)
