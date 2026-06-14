#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <unistd.h>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam_time_wait_prelude.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_unacceptable_11_sm.h"

namespace tc8::sce::cases {

using TcpUnacceptable11SM = ::SCE::Generated::tcp_unacceptable_11::tcp_unacceptable_11;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpUnacceptable11SM>
    : TcpAnyBase<cases::TcpUnacceptable11SM> {
    static constexpr std::string_view kCaseId       = "TCP_UNACCEPTABLE_11";
    static constexpr std::string_view kSpecSection  = "4.8.6.3";
    static constexpr std::string_view kDescription  =
        "TCP in CLOSING state MUST return ACK with proper SEQ and "
        "ACK numbers after receiving a segment with OTW SEQ or "
        "unacceptable ACK number (RFC 793 §3.4 p37). 2 spec "
        "iterations exercise CASE 1 (OTW SEQ) and CASE 2 (unacc ACK)";

    static constexpr std::array<std::uint8_t, 4> kCorruptPayload = {
        0xCAU, 0xFEU, 0xBAU, 0xBEU};

    // Migrated onto the Tier-2 DUT-control seam: active OPEN via
    // driveSeamActiveOpen + DUT CLOSE via driveSeamCloseToClosing
    // (closeTcp), so the case runs unchanged on whichever backend
    // --dut-control selected. The tester-side AutoAckDrop, corrupt
    // probe, and silent dispose stay case-owned.
    //
    // Function-scoped TesterAutoAckDrop covers both phases. Per phase:
    // distinct port quad active-OPEN handshake → driveSeamCloseToClosing
    // (DUT close via closeTcp + non-acking tester FIN+ACK injection
    // drives DUT FW1 → CLOSING) → CASE-distinct corrupt segment → DUT
    // empty ACK → silentlyCloseTesterFd (TCP_REPAIR + close, no tester
    // FIN emitted, frees the 4-tuple cleanly between phases).
    //
    // Phase 1 (CASE 1 OTW SEQ): seq = tester_seq_post_fin +
    // kOutOfWindowSeqOffset; ack = tester_ack_post_fin (acceptable,
    // doesn't trip tcp_ack short-circuit). Linux's
    // tcp_validate_incoming OTW SEQ branch fires before tcp_ack —
    // challenge ACK observed.
    //
    // Phase 2 (CASE 2 unacceptable ACK): seq = tester_seq_post_fin
    // (acceptable, in-window); ack = tester_ack_post_fin +
    // kUnacceptableAckOffset (after(ack, snd_nxt)). Empirically
    // verified 2026-04-26 — DUT empty ACK is observed in CLOSING.
    // CLOSING joins FIN-WAIT-1 (UNACCEPTABLE_09) and CLOSE-WAIT
    // (UNACCEPTABLE_14) in honouring CASE 2; siblings ESTABLISHED
    // (_04), FIN-WAIT-2 (_10), and LAST-ACK (_12) silent-drop via
    // tcp_ack short-circuit but the CLOSING handler takes a
    // different branch and emits a dup-ACK on the data path.
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        TesterAutoAckDrop ack_drop(cfg);
        (void)ack_drop;

        // Per-phase unique 4-tuples from the +200 reservation block. Each
        // phase establishes then closes the DUT through CLOSING to LAST-ACK,
        // leaving a ~60 s LAST_ACK residue, so the two phase offsets must
        // differ from each other AND from sibling UNACCEPTABLE_12 — otherwise
        // a same-worker bind hits EADDRNOTAVAIL (the BASICS_11 collision
        // class, reference_active_open_port_quad_collision.md).
        constexpr std::array<std::uint16_t, 2> kPhaseOffsets = {
            kTcpUnacceptable11Phase1LocalOffset,
            kTcpUnacceptable11Phase2LocalOffset};

        for (std::uint16_t phase = 0; phase < 2U; ++phase) {
            const std::uint16_t offset      = kPhaseOffsets[phase];
            const std::uint16_t local_port  = kBasicsActiveLocalPort  + offset;
            const std::uint16_t remote_port = kBasicsActiveRemotePort + offset;

            auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
            const int tester_fd = open.listener.acceptOne();
            if (tester_fd < 0 || !open.conn) {
                silentlyCloseTesterFd(tester_fd);
                std::this_thread::sleep_for(kTcpPilotPhaseGap);
                continue;
            }

            const auto info = driveSeamCloseToClosing(
                dut, cfg, iface, tester_fd, open.conn->socket,
                local_port, remote_port);
            if (!info.ok) {
                silentlyCloseTesterFd(tester_fd);
                std::this_thread::sleep_for(kTcpPilotPhaseGap);
                continue;
            }

            // Spec literal "ACK with proper SEQ and ACK numbers" — DUT
            // emits a pure ACK on the data path with ack_num == DUT.rcv.
            // nxt at injection. CLOSING reached this point via tester
            // FIN consuming a virtual byte, so DUT.rcv.nxt == tester.
            // snd_nxt == info.tester_seq_post_fin. Empirically confirmed
            // via pcap 2026-05-07 for both CASE 1 (dup-ACK from OTW
            // SEQ short-circuit) and CASE 2 (challenge ACK from
            // tcp_send_challenge_ack on after(ack, snd_nxt)).
            if (phase == 0U) {
                c.expected_ack_num        = info.tester_seq_post_fin;
            } else {
                c.expected_ack_num_phase2 = info.tester_seq_post_fin;
            }
            ::tc8::stimulus::TcpSegmentSpec data{};
            data.src_port = remote_port;
            data.dst_port = local_port;
            if (phase == 0U) {  // CASE 1: OTW SEQ
                data.seq_num = info.tester_seq_post_fin + kOutOfWindowSeqOffset;
                data.ack_num = info.tester_ack_post_fin;
            } else {            // CASE 2: unacceptable ACK
                data.seq_num = info.tester_seq_post_fin;
                data.ack_num = info.tester_ack_post_fin + kUnacceptableAckOffset;
            }
            data.flags   = ::tc8::stimulus::kTcpFlagPsh
                         | ::tc8::stimulus::kTcpFlagAck;
            data.payload.assign(kCorruptPayload.begin(),
                                kCorruptPayload.end());
            emitTcpFrame(cfg, iface, cfg.dut.mac, data,
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
            case State::Fail_p1_no_probe_ack:       return "fail:no_dut_ack_to_otw_seq_in_closing";
            case State::Fail_p2_no_handshake_ack:   return "fail:no_dut_handshake_ack_phase2";
            case State::Fail_p2_no_close_fin:       return "fail:no_dut_close_fin_phase2";
            case State::Fail_p2_no_closing_ack:     return "fail:no_dut_ack_in_closing_transition_phase2";
            case State::Fail_p2_no_probe_ack:       return "fail:no_dut_ack_to_unacceptable_ack_in_closing";
            default:                                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpUnacceptable11SM, tcp_unacceptable_11)
