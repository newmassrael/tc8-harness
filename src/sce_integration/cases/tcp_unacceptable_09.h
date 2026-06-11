#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <unistd.h>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_unacceptable_09_sm.h"

namespace tc8::sce::cases {

using TcpUnacceptable09SM = ::SCE::Generated::tcp_unacceptable_09::tcp_unacceptable_09;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpUnacceptable09SM>
    : TcpAnyBase<cases::TcpUnacceptable09SM> {
    static constexpr std::string_view kCaseId       = "TCP_UNACCEPTABLE_09";
    static constexpr std::string_view kSpecSection  = "4.8.6.3";
    static constexpr std::string_view kDescription  =
        "TCP in FIN-WAIT-1 state MUST return ACK with proper SEQ and "
        "ACK numbers after receiving a segment with OTW SEQ or "
        "unacceptable ACK (RFC 793 §3.4 p37 Establishing a Connection)";

    static constexpr std::array<std::uint8_t, 4> kCorruptPayload = {
        0xCAU, 0xFEU, 0xBAU, 0xBEU};

    // Spec Test Procedure (v3.0 p301-p320.txt:565), two iterations:
    //   * Phase 1 — data segment with OTW SEQ.
    //   * Phase 2 — data segment with unacceptable ACK number.
    //
    // Per phase:
    //   1. Active-OPEN handshake → ESTABLISHED (DUT-side bind/connect
    //      via UT OpOpenTcpSocket(Active) against tester listener).
    //   2. Install TesterAutoAckDrop — iptables OUTPUT drops tester-
    //      kernel pure ACK toward DUT. Without this, the auto-ACK to
    //      DUT FIN advances DUT into FIN-WAIT-2, collapsing the
    //      spec-targeted state.
    //   3. UT OpCloseTcpSocket — DUT app close() → DUT emits FIN →
    //      DUT enters FIN-WAIT-1. (Tester ACK suppressed by step 2.)
    //   4. 100 ms settle wait — let Linux flush the FIN onto pcap and
    //      stabilise tester socket TCP state (CLOSE-WAIT after rcv-
    //      side processing of DUT FIN) before TCP_REPAIR query.
    //   5. queryTcpSeqRange(tester_fd) — read tester snd_nxt /
    //      rcv_nxt. rcv_nxt now reflects DUT FIN (advanced by 1 from
    //      pre-FIN); snd_nxt unchanged because tester wrote no data.
    //   6. Build corrupt segment per CASE:
    //        * CASE 1 (OTW SEQ): seq_num = snd_nxt +
    //                  kOutOfWindowSeqOffset (OTW per RFC 793 §3.3
    //                  p25), ack_num = rcv_nxt - 1 — an "old" ACK
    //                  that is acceptable per RFC 793 §3.4 (falls
    //                  inside snd.una..snd.nxt) but does NOT
    //                  acknowledge the DUT FIN. ack_num == rcv_nxt
    //                  would ACK the FIN and advance DUT into
    //                  FIN-WAIT-2, losing the FIN-WAIT-1 fidelity.
    //        * CASE 2 (unacceptable ACK): seq_num = snd_nxt (in-
    //                  window), ack_num = rcv_nxt +
    //                  kUnacceptableAckOffset (unacceptable per
    //                  RFC 793 §3.9 p70). The unacceptable ACK is
    //                  the spec-asserted edge; the in-window SEQ
    //                  ensures tcp_validate_incoming does NOT
    //                  short-circuit at the OTW path before
    //                  tcp_ack examines the ACK.
    //   7. Pcap observes DUT empty ACK on the data path.
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        // -------- Phase 1: OTW SEQ in FIN-WAIT-1 --------
        {
            auto listener = driveActiveOpenEstablished(
                cfg, iface, cfg.dut.mac,
                /*open_req_id=*/1,
                kBasicsActiveLocalPort  + kTcpUnacceptable09Phase1LocalOffset,
                kBasicsActiveRemotePort + kTcpUnacceptable09Phase1LocalOffset);
            const int tester_fd = listener.acceptOne();
            TesterAutoAckDrop ack_drop(cfg);
            // UT close drives DUT into FIN-WAIT-1 (no tester ACK
            // because of ack_drop).
            sendCloseTcpSocketRequest(
                cfg, iface, cfg.dut.mac,
                /*req_id=*/2, /*socket_id=*/1);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            if (tester_fd >= 0) {
                const auto seq_range = queryTcpSeqRange(tester_fd);
                if (seq_range.has_value()) {
                    // Spec literal "ACK with proper SEQ and ACK numbers" —
                    // DUT challenge ACK in FW-1 (OTW SEQ → tcp_send_dupack
                    // before tcp_ack) carries ack_num == DUT.rcv.nxt ==
                    // tester.snd_nxt at injection time. Empirically
                    // confirmed via pcap 2026-05-07.
                    c.expected_ack_num = seq_range->snd_nxt;
                    ::tc8::stimulus::TcpSegmentSpec data{};
                    data.src_port = kBasicsActiveRemotePort + kTcpUnacceptable09Phase1LocalOffset;
                    data.dst_port = kBasicsActiveLocalPort  + kTcpUnacceptable09Phase1LocalOffset;
                    data.seq_num  = seq_range->snd_nxt + kOutOfWindowSeqOffset;
                    data.ack_num  = seq_range->rcv_nxt - 1U;
                    data.flags    = ::tc8::stimulus::kTcpFlagPsh
                                  | ::tc8::stimulus::kTcpFlagAck;
                    data.payload.assign(kCorruptPayload.begin(),
                                        kCorruptPayload.end());
                    emitTcpFrame(cfg, iface, cfg.dut.mac, data,
                                 /*initial_wait=*/std::chrono::milliseconds(0));
                }
                (void)tester_fd;
            }
            std::this_thread::sleep_for(kTcpPilotPhaseGap);
        }

        // -------- Phase 2: unacceptable ACK in FIN-WAIT-1 --------
        {
            const std::uint16_t phase2_local_port  = kBasicsActiveLocalPort  + kTcpUnacceptable09Phase2LocalOffset;
            const std::uint16_t phase2_remote_port = kBasicsActiveRemotePort + kTcpUnacceptable09Phase2LocalOffset;

            auto listener = driveActiveOpenEstablished(
                cfg, iface, cfg.dut.mac,
                /*open_req_id=*/3,
                /*local_port=*/phase2_local_port,
                /*remote_port=*/phase2_remote_port);
            const int tester_fd = listener.acceptOne();
            TesterAutoAckDrop ack_drop(cfg);
            sendCloseTcpSocketRequest(
                cfg, iface, cfg.dut.mac,
                /*req_id=*/4, /*socket_id=*/2);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            if (tester_fd >= 0) {
                const auto seq_range = queryTcpSeqRange(tester_fd);
                if (seq_range.has_value()) {
                    // Unacceptable ACK in FW-1: tcp_ack returns invalid
                    // (after(ack, snd_nxt)) → tcp_send_challenge_ack with
                    // tp->rcv.nxt unchanged because tcp_data_queue is
                    // bypassed via discard_and_undo. ack_num == tester.
                    // snd_nxt at injection. Phase 2 has its own active-
                    // OPEN with kernel-chosen ISN_t, so a separate slot
                    // is required (the harness-model writes captured
                    // fields exactly once, before dispatch starts).
                    c.expected_ack_num_phase2 = seq_range->snd_nxt;
                    ::tc8::stimulus::TcpSegmentSpec data{};
                    data.src_port = phase2_remote_port;
                    data.dst_port = phase2_local_port;
                    data.seq_num  = seq_range->snd_nxt;
                    data.ack_num  = seq_range->rcv_nxt + kUnacceptableAckOffset;
                    data.flags    = ::tc8::stimulus::kTcpFlagPsh
                                  | ::tc8::stimulus::kTcpFlagAck;
                    data.payload.assign(kCorruptPayload.begin(),
                                        kCorruptPayload.end());
                    emitTcpFrame(cfg, iface, cfg.dut.mac, data,
                                 /*initial_wait=*/std::chrono::milliseconds(0));
                }
                (void)tester_fd;
            }
            std::this_thread::sleep_for(kTcpPilotPhaseGap);
        }
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                          return "pass";
            case State::Fail_p1_no_handshake_ack:      return "fail:no_dut_handshake_ack_phase1";
            case State::Fail_p1_no_dut_fin:            return "fail:no_dut_fin_phase1";
            case State::Fail_p1_no_data_ack:           return "fail:no_dut_ack_to_otw_seq_finwait1";
            case State::Fail_p2_no_handshake_ack:      return "fail:no_dut_handshake_ack_phase2";
            case State::Fail_p2_no_dut_fin:            return "fail:no_dut_fin_phase2";
            case State::Fail_p2_no_data_ack:           return "fail:no_dut_ack_to_unacceptable_ack_finwait1";
            default:                                   return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpUnacceptable09SM, tcp_unacceptable_09)
