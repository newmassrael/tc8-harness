#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <unistd.h>

#include <sys/socket.h>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_unacceptable_12_sm.h"

namespace tc8::sce::cases {

using TcpUnacceptable12SM = ::SCE::Generated::tcp_unacceptable_12::tcp_unacceptable_12;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpUnacceptable12SM>
    : TcpAnyBase<cases::TcpUnacceptable12SM> {
    static constexpr std::string_view kCaseId       = "TCP_UNACCEPTABLE_12";
    static constexpr std::string_view kSpecSection  = "4.8.6.3";
    static constexpr std::string_view kDescription  =
        "TCP in LAST-ACK state MUST return ACK with proper SEQ and "
        "ACK numbers after receiving a segment with OTW SEQ or "
        "unacceptable ACK (RFC 793 §3.4 p37). 2 spec iterations "
        "exercise CASE 1 (OTW SEQ) and CASE 2 (unacc ACK)";

    static constexpr std::array<std::uint8_t, 4> kCorruptPayload = {
        0xCAU, 0xFEU, 0xBAU, 0xBEU};

    // Function-scoped TesterAutoAckDrop covers both phases. Per phase:
    // distinct port quad active-OPEN handshake → tester shutdown(WR)
    // (tester FIN+ACK, DUT auto-ACK observed, DUT CLOSE-WAIT) → UT
    // close (DUT FIN+ACK observed; tester pure ACK to DUT FIN
    // suppressed by ack_drop, DUT pinned in LAST-ACK) →
    // queryTcpSeqRange(tester_fd) → CASE-distinct corrupt segment →
    // DUT empty ACK → silentlyCloseTesterFd (TCP_REPAIR + close, no
    // tester FIN emitted, frees the 4-tuple cleanly between phases).
    //
    // Phase 1 (CASE 1 OTW SEQ): seq = snd_nxt + kOutOfWindowSeqOffset;
    // ack = rcv_nxt - 1 (acceptable per RFC 793 §3.4 — falls in
    // [snd.una, snd.nxt) — but does NOT acknowledge DUT FIN so DUT
    // stays in LAST-ACK). Linux's tcp_validate_incoming OTW SEQ branch
    // fires before tcp_ack — challenge ACK observed.
    //
    // Phase 2 (CASE 2 unacceptable ACK): seq = snd_nxt (in-window);
    // ack = rcv_nxt - 1 + kUnacceptableAckOffset (after(ack, snd_nxt)).
    // Per Linux 6.5 net/ipv4/tcp_input.c line 6562-6568, LAST-ACK
    // dispatches via tcp_rcv_state_process with FLAG_NO_CHALLENGE_ACK;
    // when tcp_ack returns !acceptable, the caller explicitly invokes
    // tcp_send_challenge_ack(sk) → DUT empty ACK observed. LAST-ACK
    // joins FIN-WAIT-1 (UNACCEPTABLE_09), CLOSING (UNACCEPTABLE_11),
    // and CLOSE-WAIT (UNACCEPTABLE_14) in honouring CASE 2; only EST
    // (_04) and FW2 orphan (_10) deviate (silent-drop and RST
    // respectively, see reference_unacc_ack_dispatch).
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        TesterAutoAckDrop ack_drop(cfg);
        (void)ack_drop;

        for (std::uint16_t phase = 0; phase < 2U; ++phase) {
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

            ::shutdown(tester_fd, SHUT_WR);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            sendCloseTcpSocketRequest(
                cfg, iface, cfg.dut.mac,
                close_req_id, socket_id);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));

            const auto seq_range = queryTcpSeqRange(tester_fd);
            if (!seq_range.has_value()) {
                silentlyCloseTesterFd(tester_fd);
                std::this_thread::sleep_for(kTcpPilotPhaseGap);
                continue;
            }

            // Spec literal "ACK with proper SEQ and ACK numbers" — DUT
            // emits a pure ACK on the data path with ack_num == DUT.rcv.
            // nxt at injection. Tester FIN advanced rcv.nxt earlier, so
            // the value equals tester.snd_nxt == seq_range->snd_nxt.
            // Empirically confirmed via pcap 2026-05-07 for both CASE 1
            // (OTW SEQ → tcp_send_dupack) and CASE 2 (LAST-ACK explicit
            // tcp_send_challenge_ack on after(ack, snd_nxt)).
            if (phase == 0U) {
                c.expected_ack_num        = seq_range->snd_nxt;
            } else {
                c.expected_ack_num_phase2 = seq_range->snd_nxt;
            }
            ::tc8::stimulus::TcpSegmentSpec data{};
            data.src_port = remote_port;
            data.dst_port = local_port;
            if (phase == 0U) {  // CASE 1: OTW SEQ
                data.seq_num = seq_range->snd_nxt + kOutOfWindowSeqOffset;
                data.ack_num = seq_range->rcv_nxt - 1U;
            } else {            // CASE 2: unacceptable ACK
                data.seq_num = seq_range->snd_nxt;
                data.ack_num = seq_range->rcv_nxt - 1U + kUnacceptableAckOffset;
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
            case State::Fail_p1_no_close_wait_ack:  return "fail:no_dut_close_wait_ack_phase1";
            case State::Fail_p1_no_dut_fin:         return "fail:no_dut_fin_phase1";
            case State::Fail_p1_no_probe_ack:       return "fail:no_dut_ack_to_otw_seq_in_last_ack";
            case State::Fail_p2_no_handshake_ack:   return "fail:no_dut_handshake_ack_phase2";
            case State::Fail_p2_no_close_wait_ack:  return "fail:no_dut_close_wait_ack_phase2";
            case State::Fail_p2_no_dut_fin:         return "fail:no_dut_fin_phase2";
            case State::Fail_p2_no_probe_ack:       return "fail:no_dut_ack_to_unacceptable_ack_in_last_ack";
            default:                                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpUnacceptable12SM, tcp_unacceptable_12)
