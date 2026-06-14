#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <unistd.h>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam_active_open.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_out_of_order_03_sm.h"

namespace tc8::sce::cases {

using TcpOutOfOrder03SM =
    ::SCE::Generated::tcp_out_of_order_03::tcp_out_of_order_03;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpOutOfOrder03SM>
    : TcpAnyBase<cases::TcpOutOfOrder03SM> {
    static constexpr std::string_view kCaseId       = "TCP_OUT_OF_ORDER_03";
    static constexpr std::string_view kSpecSection  = "4.8.6.10";
    static constexpr std::string_view kDescription  =
        "DUT TCP queues out-of-order segments and emits a cumulative ACK "
        "covering all queued data once the SEQ-number gap is filled "
        "(RFC 1122 §4.2.2.20 / RFC 793 §3.9).";

    // Wire layout per case:
    //   SEG0     [S,    S+4)    — in-order, ACKed at S+4 (phase 1).
    //   gap      [S+4,  S+8)    — 4 bytes withheld until SEG_FILL.
    //   SEG_GAP1 [S+8,  S+12)   — OOO, queued.
    //   SEG_GAP2 [S+12, S+16)   — OOO, queued.
    //   SEG_FILL [S+4,  S+8)    — closes the gap; DUT emits cumulative
    //                             ACK at S+16 (phase 2).
    // Distinct first byte per segment ('A'/'B'/'C'/'C') keeps each
    // segment visually identifiable in pcap; the exact bytes are not
    // load-bearing — only the SEQ ranges and segment count matter.
    static constexpr std::array<std::uint8_t, 4> kSeg0Payload = {
        'A', '0', 'A', '1'};
    static constexpr std::array<std::uint8_t, 4> kSegGap1Payload = {
        'C', '0', 'C', '1'};
    static constexpr std::array<std::uint8_t, 4> kSegGap2Payload = {
        'C', '2', 'C', '3'};
    static constexpr std::array<std::uint8_t, 4> kSegFillPayload = {
        'B', '0', 'B', '1'};

    // 5 ms inter-segment pacing so the kernel has time to emit each
    // ACK on the wire in the same order the segments were sent;
    // without this, all four sends can be packed into a single
    // pcap snapshot interval and the SCXML's per-state event
    // ordering (handshake_ack -> initial_ack -> cumulative_ack)
    // becomes order-of-arrival sensitive at the dispatch layer.
    static constexpr std::chrono::milliseconds kInterSegmentWait{5};

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  =
            kBasicsActiveLocalPort  + kTcpOutOfOrder03LocalOffset;
        const std::uint16_t remote_port =
            kBasicsActiveRemotePort + kTcpOutOfOrder03LocalOffset;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0) return;

        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (!seq_range.has_value()) {
            ::close(tester_fd);
            return;
        }

        const std::uint32_t injected_seq = seq_range->snd_nxt;
        const std::uint32_t seg_len      =
            static_cast<std::uint32_t>(kSeg0Payload.size());
        // Phase-1 cumulative ack: covers SEG0 only.
        c.expected_ack_num        = injected_seq + seg_len;
        // Phase-2 cumulative ack: covers SEG0 + SEG_FILL +
        // SEG_GAP1 + SEG_GAP2 = 4 * 4 = 16 bytes.
        c.expected_ack_num_phase2 = injected_seq + 4U * seg_len;

        const auto build_seg = [&](std::uint32_t seq,
                                   const std::array<std::uint8_t, 4>& bytes) {
            ::tc8::stimulus::TcpSegmentSpec spec{};
            spec.src_port = remote_port;
            spec.dst_port = local_port;
            spec.seq_num  = seq;
            spec.ack_num  = seq_range->rcv_nxt;
            spec.flags    = ::tc8::stimulus::kTcpFlagAck
                          | ::tc8::stimulus::kTcpFlagPsh;
            spec.payload.assign(bytes.begin(), bytes.end());
            return spec;
        };

        emitTcpFrame(cfg, iface, cfg.dut.mac,
                     build_seg(injected_seq, kSeg0Payload),
                     /*initial_wait=*/std::chrono::milliseconds(0));
        emitTcpFrame(cfg, iface, cfg.dut.mac,
                     build_seg(injected_seq + 2U * seg_len, kSegGap1Payload),
                     kInterSegmentWait);
        emitTcpFrame(cfg, iface, cfg.dut.mac,
                     build_seg(injected_seq + 3U * seg_len, kSegGap2Payload),
                     kInterSegmentWait);
        emitTcpFrame(cfg, iface, cfg.dut.mac,
                     build_seg(injected_seq + seg_len, kSegFillPayload),
                     kInterSegmentWait);
        (void)tester_fd;
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                            return "pass";
            case State::Fail_no_handshake_ack:           return "fail:no_dut_handshake_ack";
            case State::Fail_no_initial_ack:             return "fail:no_dut_ack_to_initial_data_segment";
            case State::Fail_no_final_cumulative_ack:    return "fail:dut_did_not_emit_cumulative_ack_after_gap_fill";
            default:                                     return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpOutOfOrder03SM, tcp_out_of_order_03)
