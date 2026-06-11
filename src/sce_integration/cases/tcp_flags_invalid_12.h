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

#include "tcp_flags_invalid_12_sm.h"

namespace tc8::sce::cases {

using TcpFlagsInvalid12SM = ::SCE::Generated::tcp_flags_invalid_12::tcp_flags_invalid_12;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpFlagsInvalid12SM>
    : TcpAnyBase<cases::TcpFlagsInvalid12SM> {
    static constexpr std::string_view kCaseId       = "TCP_FLAGS_INVALID_12";
    static constexpr std::string_view kSpecSection  = "4.8.6.6";
    static constexpr std::string_view kDescription  =
        "TCP in CLOSING state MUST send an ACK with next expected "
        "SEQ number after receiving any segment with OTW SEQ number "
        "(RFC 793 §3.9 p69 Event Processing). 5 spec iterations "
        "exercise flag set ∈ {SYN, SYN+ACK, ACK, FIN, data}";

    static constexpr std::array<std::uint8_t, 4> kCorruptPayload = {
        0xCAU, 0xFEU, 0xBAU, 0xBEU};

    // Function-scoped TesterAutoAckDrop installed at top: iptables
    // OUTPUT drops tester-kernel pure ACK toward DUT for the entire
    // stimulus, preventing the auto-ACK to DUT FIN from advancing
    // DUT past FIN-WAIT-1 on every phase. Per phase: distinct port
    // quad active-OPEN handshake → UT close (kernel auto-ACK
    // suppressed → DUT pinned in FW1) → driveCloseToClosing raw-
    // injects tester FIN+ACK with non-acking ack (ack = rcv_nxt - 1)
    // → DUT FW1 → CLOSING with DUT pure ACK observation → CASE-
    // distinct OTW probe (seq = tester_seq_post_fin +
    // kOutOfWindowSeqOffset) → DUT challenge ACK (RFC 793 §3.9) →
    // silentlyCloseTesterFd (TCP_REPAIR + close, no tester FIN
    // emitted, frees the 4-tuple cleanly).
    //
    // Probes for CASE 2..5 carry ack = info.tester_ack_post_fin - 1U
    // (= rcv_nxt - 1, acceptable per RFC 793 §3.4 but does NOT
    // acknowledge DUT FIN). Linux's tcp_validate_incoming OTW SEQ
    // check fires before tcp_ack, so the ACK value is moot for the
    // spec-asserted challenge-ACK path; using rcv_nxt - 1 is belt-
    // and-suspenders against any hypothetical lenient-OTW edge that
    // would otherwise advance DUT past CLOSING via FIN consumption.
    // Same convention as FLAGS_INVALID_09 (FW1) and FLAGS_INVALID_13
    // (LAST-ACK).
    //
    // CASE 4 (FIN) carries an ACK flag — Linux's tcp_v4_rcv silent-
    // drops bare-FIN segments before reaching tcp_validate_incoming's
    // OTW SEQ branch, so carrying ACK keeps the segment past the
    // early-drop. Same convention as FLAGS_INVALID_08 / _09 / _10 /
    // _11 / _13.
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        TesterAutoAckDrop ack_drop(cfg);
        (void)ack_drop;

        for (std::uint16_t phase = 0; phase < 5U; ++phase) {
            const std::uint16_t local_port  = kBasicsActiveLocalPort  + phase;
            const std::uint16_t remote_port = kBasicsActiveRemotePort + phase;
            const std::uint8_t open_req_id =
                static_cast<std::uint8_t>(1U + phase * 2U);
            const std::uint8_t close_req_id =
                static_cast<std::uint8_t>(2U + phase * 2U);
            const std::uint8_t socket_id =
                static_cast<std::uint8_t>(phase + 1U);

            auto listener = driveActiveOpenEstablished(
                cfg, iface, cfg.dut.mac,
                open_req_id, local_port, remote_port);
            const int tester_fd = listener.acceptOne();
            if (tester_fd < 0) {
                std::this_thread::sleep_for(kTcpPilotPhaseGap);
                continue;
            }

            const auto info = driveCloseToClosing(
                cfg, iface, cfg.dut.mac, tester_fd,
                close_req_id, socket_id, local_port, remote_port);
            if (!info.ok) {
                silentlyCloseTesterFd(tester_fd);
                std::this_thread::sleep_for(kTcpPilotPhaseGap);
                continue;
            }

            // Spec literal "ACK with next expected SEQ number" — DUT
            // challenge ACK in CLOSING carries ack_num == DUT.rcv.nxt
            // == info.tester_seq_post_fin (tester FIN already
            // consumed when entering CLOSING). Per-phase slot because
            // each phase opens a fresh active-OPEN with kernel-chosen
            // ISN_t.
            switch (phase) {
                case 0:  c.expected_ack_num        = info.tester_seq_post_fin; break;
                case 1:  c.expected_ack_num_phase2 = info.tester_seq_post_fin; break;
                case 2:  c.expected_ack_num_phase3 = info.tester_seq_post_fin; break;
                case 3:  c.expected_ack_num_phase4 = info.tester_seq_post_fin; break;
                default: c.expected_ack_num_phase5 = info.tester_seq_post_fin; break;
            }
            ::tc8::stimulus::TcpSegmentSpec probe{};
            probe.src_port = remote_port;
            probe.dst_port = local_port;
            probe.seq_num  = info.tester_seq_post_fin + kOutOfWindowSeqOffset;
            switch (phase) {
                case 0:  // CASE 1: SYN-only
                    probe.flags   = ::tc8::stimulus::kTcpFlagSyn;
                    probe.ack_num = 0U;
                    break;
                case 1:  // CASE 2: SYN+ACK
                    probe.flags   = ::tc8::stimulus::kTcpFlagSyn
                                  | ::tc8::stimulus::kTcpFlagAck;
                    probe.ack_num = info.tester_ack_post_fin - 1U;
                    break;
                case 2:  // CASE 3: ACK
                    probe.flags   = ::tc8::stimulus::kTcpFlagAck;
                    probe.ack_num = info.tester_ack_post_fin - 1U;
                    break;
                case 3:  // CASE 4: FIN+ACK
                    probe.flags   = ::tc8::stimulus::kTcpFlagFin
                                  | ::tc8::stimulus::kTcpFlagAck;
                    probe.ack_num = info.tester_ack_post_fin - 1U;
                    break;
                default:  // CASE 5: data segment
                    probe.flags   = ::tc8::stimulus::kTcpFlagPsh
                                  | ::tc8::stimulus::kTcpFlagAck;
                    probe.ack_num = info.tester_ack_post_fin - 1U;
                    probe.payload.assign(kCorruptPayload.begin(),
                                         kCorruptPayload.end());
                    break;
            }
            emitTcpFrame(cfg, iface, cfg.dut.mac, probe,
                         /*initial_wait=*/std::chrono::milliseconds(0));
            std::this_thread::sleep_for(std::chrono::milliseconds(100));

            silentlyCloseTesterFd(tester_fd);
            std::this_thread::sleep_for(kTcpPilotPhaseGap);
        }
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                       return "pass";
            case State::Fail_p1_no_handshake_ack:   return "fail:no_dut_handshake_ack_phase1";
            case State::Fail_p1_no_close_fin:       return "fail:no_dut_close_fin_phase1";
            case State::Fail_p1_no_closing_ack:     return "fail:no_dut_ack_in_closing_transition_phase1";
            case State::Fail_p1_no_probe_ack:       return "fail:no_dut_ack_to_otw_seq_syn_in_closing";
            case State::Fail_p2_no_handshake_ack:   return "fail:no_dut_handshake_ack_phase2";
            case State::Fail_p2_no_close_fin:       return "fail:no_dut_close_fin_phase2";
            case State::Fail_p2_no_closing_ack:     return "fail:no_dut_ack_in_closing_transition_phase2";
            case State::Fail_p2_no_probe_ack:       return "fail:no_dut_ack_to_otw_seq_synack_in_closing";
            case State::Fail_p3_no_handshake_ack:   return "fail:no_dut_handshake_ack_phase3";
            case State::Fail_p3_no_close_fin:       return "fail:no_dut_close_fin_phase3";
            case State::Fail_p3_no_closing_ack:     return "fail:no_dut_ack_in_closing_transition_phase3";
            case State::Fail_p3_no_probe_ack:       return "fail:no_dut_ack_to_otw_seq_ack_in_closing";
            case State::Fail_p4_no_handshake_ack:   return "fail:no_dut_handshake_ack_phase4";
            case State::Fail_p4_no_close_fin:       return "fail:no_dut_close_fin_phase4";
            case State::Fail_p4_no_closing_ack:     return "fail:no_dut_ack_in_closing_transition_phase4";
            case State::Fail_p4_no_probe_ack:       return "fail:no_dut_ack_to_otw_seq_fin_in_closing";
            case State::Fail_p5_no_handshake_ack:   return "fail:no_dut_handshake_ack_phase5";
            case State::Fail_p5_no_close_fin:       return "fail:no_dut_close_fin_phase5";
            case State::Fail_p5_no_closing_ack:     return "fail:no_dut_ack_in_closing_transition_phase5";
            case State::Fail_p5_no_probe_ack:       return "fail:no_dut_ack_to_otw_seq_data_in_closing";
            default:                                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsInvalid12SM, tcp_flags_invalid_12)
