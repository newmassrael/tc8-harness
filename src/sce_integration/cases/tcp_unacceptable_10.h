#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>
#include <unistd.h>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam_active_open.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_unacceptable_10_sm.h"

namespace tc8::sce::cases {

using TcpUnacceptable10SM = ::SCE::Generated::tcp_unacceptable_10::tcp_unacceptable_10;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpUnacceptable10SM>
    : TcpAnyBase<cases::TcpUnacceptable10SM> {
    static constexpr std::string_view kCaseId       = "TCP_UNACCEPTABLE_10";
    static constexpr std::string_view kSpecSection  = "4.8.6.3";
    static constexpr std::string_view kDescription  =
        "TCP in FIN-WAIT-2 state MUST return ACK with proper SEQ and "
        "ACK numbers after receiving a segment with OTW SEQ or "
        "unacceptable ACK (RFC 793 §3.4 p37 Establishing a Connection)";

    static constexpr std::array<std::uint8_t, 4> kCorruptPayload = {
        0xCAU, 0xFEU, 0xBAU, 0xBEU};

    // Spec Test Procedure (v3.0 p301-p320.txt:609), two iterations,
    // both exercised:
    //   * Phase 1 — fired synchronously: data segment with OTW SEQ
    //     (snd_nxt + kOutOfWindowSeqOffset).
    //   * Phase 2 — deferred via scheduleAfterStateEntry on
    //     Listening_unacc_ack: data segment with in-window SEQ +
    //     unacceptable ACK (snd_nxt + kOutOfWindowSeqOffset).
    //
    // Linux 6.5 FW2 substate emits RST not ACK on phase 2's unacc-ACK
    // (`tcp_minisocks.c::tcp_timewait_state_process` line 130-135 →
    // `tcp_v4_send_reset`). Linux DUT therefore lands
    // `fail_dut_rst_to_unacc_ack`; case is excluded from CI green via
    // grep filter in .github/workflows/smoke-test.yml. A spec-compliant
    // DUT emitting an empty ACK lands pass without filter. See SCXML
    // preamble + reference_unacc_ack_dispatch memory for the source
    // trace.
    //
    // Mechanism:
    //   1. Active-OPEN handshake → ESTABLISHED.
    //   2. The seam CLOSE — DUT FIN → DUT enters FIN-WAIT-1.
    //   3. Tester kernel auto-ACKs DUT FIN (NOT suppressed) → DUT
    //      transitions FIN-WAIT-1 → FIN-WAIT-2. The 200 ms settle
    //      wait covers the auto-ACK round-trip + tester socket TCP
    //      state stabilisation before TCP_REPAIR query.
    //   4. queryTcpSeqRange(tester_fd) — tester snd_nxt = ISN_t + 1
    //      (no tester data); rcv_nxt = ISN_d + 2 (DUT FIN
    //      consumed +1).
    //   5. Phase 1 — build OTW-SEQ corrupt segment: seq_num =
    //      snd_nxt + kOutOfWindowSeqOffset, ack_num = rcv_nxt;
    //      payload from kCorruptPayload. Pcap observes DUT empty
    //      ACK on the data path.
    //   6. Phase 2 — on listening_unacc_ack entry, re-query seq
    //      range and inject in-window SEQ (tester snd_nxt) +
    //      unacceptable ACK (tester rcv_nxt + kUnacceptableAckOffset).
    //      Linux FW2 substate RSTs (Linux deviation); spec-compliant
    //      DUT emits empty ACK. Same stimulus shape as
    //      UNACCEPTABLE_09 CASE 2.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut,
                         IStimulusScheduler& scheduler) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        auto open = driveSeamActiveOpen(
            dut, cfg,
            kBasicsActiveLocalPort  + kTcpUnacceptable10LocalOffset,
            kBasicsActiveRemotePort + kTcpUnacceptable10LocalOffset);
        const int tester_fd = open.listener.acceptOne();
        if (open.conn) dut.tcpControl()->closeTcp(open.conn->socket);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        if (tester_fd < 0) return;

        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (!seq_range.has_value()) return;

        ::tc8::stimulus::TcpSegmentSpec phase1{};
        phase1.src_port = kBasicsActiveRemotePort + kTcpUnacceptable10LocalOffset;
        phase1.dst_port = kBasicsActiveLocalPort  + kTcpUnacceptable10LocalOffset;
        phase1.seq_num  = seq_range->snd_nxt + kOutOfWindowSeqOffset;
        phase1.ack_num  = seq_range->rcv_nxt;
        phase1.flags    = ::tc8::stimulus::kTcpFlagPsh
                        | ::tc8::stimulus::kTcpFlagAck;
        phase1.payload.assign(kCorruptPayload.begin(),
                              kCorruptPayload.end());
        emitTcpFrame(cfg, iface, cfg.dut.mac, phase1,
                     /*initial_wait=*/std::chrono::milliseconds(0));

        ::tc8::TestConfig cfg_copy = cfg;
        std::string       iface_str(iface);
        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_unacc_ack),
            [cfg_copy, iface_str, tester_fd]() {
                using namespace ::tc8::sce::tcp;
                const auto seq_range_p2 = queryTcpSeqRange(tester_fd);
                if (!seq_range_p2.has_value()) return;
                ::tc8::stimulus::TcpSegmentSpec phase2{};
                phase2.src_port = kBasicsActiveRemotePort + kTcpUnacceptable10LocalOffset;
                phase2.dst_port = kBasicsActiveLocalPort  + kTcpUnacceptable10LocalOffset;
                phase2.seq_num  = seq_range_p2->snd_nxt;
                phase2.ack_num  = seq_range_p2->rcv_nxt + kUnacceptableAckOffset;
                phase2.flags    = ::tc8::stimulus::kTcpFlagPsh
                                | ::tc8::stimulus::kTcpFlagAck;
                phase2.payload.assign(kCorruptPayload.begin(),
                                      kCorruptPayload.end());
                emitTcpFrame(cfg_copy, iface_str, cfg_copy.dut.mac, phase2,
                             /*initial_wait=*/std::chrono::milliseconds(0));
            });

        (void)tester_fd;
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                          return "pass";
            case State::Fail_no_handshake_ack:         return "fail:no_dut_handshake_ack_within_listen_window";
            case State::Fail_no_dut_fin:               return "fail:no_dut_fin_within_listen_window";
            case State::Fail_no_data_ack:              return "fail:no_dut_ack_to_otw_seq_finwait2";
            case State::Fail_dut_rst_to_unacc_ack:     return "fail:dut_rst_to_unacc_ack_finwait2";
            case State::Fail_no_dut_ack_to_unacc_ack:  return "fail:no_dut_ack_to_unacc_ack_finwait2";
            default:                                   return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpUnacceptable10SM, tcp_unacceptable_10)
