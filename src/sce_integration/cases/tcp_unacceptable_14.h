#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <unistd.h>

#include <sys/socket.h>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_unacceptable_14_sm.h"

namespace tc8::sce::cases {

using TcpUnacceptable14SM = ::SCE::Generated::tcp_unacceptable_14::tcp_unacceptable_14;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpUnacceptable14SM>
    : TcpAnyBase<cases::TcpUnacceptable14SM> {
    static constexpr std::string_view kCaseId       = "TCP_UNACCEPTABLE_14";
    static constexpr std::string_view kSpecSection  = "4.8.6.3";
    static constexpr std::string_view kDescription  =
        "TCP in CLOSE-WAIT state MUST return ACK with proper SEQ and "
        "ACK numbers after receiving a segment with OTW SEQ or "
        "unacceptable ACK (RFC 793 §3.4 p37 Establishing a Connection)";

    static constexpr std::array<std::uint8_t, 4> kCorruptPayload = {
        0xCAU, 0xFEU, 0xBAU, 0xBEU};

    // Spec Test Procedure (v3.0 p321-p340.txt:23), two iterations:
    //   * Phase 1 — data segment with OTW SEQ.
    //   * Phase 2 — data segment with unacceptable ACK number.
    //
    // Per phase: active-OPEN handshake → ESTABLISHED → tester
    // shutdown(SHUT_WR) drives DUT into CLOSE-WAIT (DUT auto-ACKs
    // tester's FIN before processing the corrupt segment) → query
    // tester snd_nxt/rcv_nxt (now reflects post-FIN values: snd_nxt
    // advanced by 1 for the consumed FIN, rcv_nxt unchanged
    // because DUT has sent no data) → raw-inject corrupt DATA → DUT
    // empty ACK on the data path.
    //
    // 100 ms post-FIN settle wait gives Linux time to emit the
    // auto-ACK before TCP_REPAIR mode reads the kernel's view of
    // SND.NXT — without it, the query can race the auto-ACK and
    // observe pre-FIN values.
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        // -------- Phase 1: OTW SEQ in CLOSE-WAIT --------
        {
            auto open = driveSeamActiveOpen(
                dut, cfg,
                kBasicsActiveLocalPort  + kTcpUnacceptable14Phase1LocalOffset,
                kBasicsActiveRemotePort + kTcpUnacceptable14Phase1LocalOffset);
            const int tester_fd = open.listener.acceptOne();
            if (tester_fd >= 0) {
                ::shutdown(tester_fd, SHUT_WR);
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                const auto seq_range = queryTcpSeqRange(tester_fd);
                if (seq_range.has_value()) {
                    // Spec literal "ACK with proper SEQ and ACK numbers" —
                    // tester FIN already advanced rcv.nxt before
                    // injection, so DUT.rcv.nxt == tester.snd_nxt ==
                    // seq_range->snd_nxt. Empirically confirmed via
                    // pcap 2026-05-07 (OTW SEQ → tcp_send_dupack;
                    // unacc ACK → tcp_send_challenge_ack on
                    // after(ack, snd_nxt)).
                    c.expected_ack_num = seq_range->snd_nxt;
                    ::tc8::stimulus::TcpSegmentSpec data{};
                    data.src_port = kBasicsActiveRemotePort + kTcpUnacceptable14Phase1LocalOffset;
                    data.dst_port = kBasicsActiveLocalPort  + kTcpUnacceptable14Phase1LocalOffset;
                    data.seq_num  = seq_range->snd_nxt + kOutOfWindowSeqOffset;
                    data.ack_num  = seq_range->rcv_nxt;
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

        // -------- Phase 2: unacceptable ACK in CLOSE-WAIT --------
        {
            const std::uint16_t phase2_local_port  = kBasicsActiveLocalPort  + kTcpUnacceptable14Phase2LocalOffset;
            const std::uint16_t phase2_remote_port = kBasicsActiveRemotePort + kTcpUnacceptable14Phase2LocalOffset;

            auto open = driveSeamActiveOpen(
                dut, cfg,
                /*local_port=*/phase2_local_port,
                /*remote_port=*/phase2_remote_port);
            const int tester_fd = open.listener.acceptOne();
            if (tester_fd >= 0) {
                ::shutdown(tester_fd, SHUT_WR);
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                const auto seq_range = queryTcpSeqRange(tester_fd);
                if (seq_range.has_value()) {
                    c.expected_ack_num_phase2 = seq_range->snd_nxt;
                    ::tc8::stimulus::TcpSegmentSpec data{};
                    data.src_port = phase2_remote_port;
                    data.dst_port = phase2_local_port;
                    data.seq_num  = seq_range->snd_nxt;
                    data.ack_num  = seq_range->rcv_nxt + kOutOfWindowSeqOffset;
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
            case State::Fail_p1_no_close_ack:          return "fail:no_dut_close_ack_phase1";
            case State::Fail_p1_no_data_ack:           return "fail:no_dut_ack_to_otw_seq_close_wait";
            case State::Fail_p2_no_handshake_ack:      return "fail:no_dut_handshake_ack_phase2";
            case State::Fail_p2_no_close_ack:          return "fail:no_dut_close_ack_phase2";
            case State::Fail_p2_no_data_ack:           return "fail:no_dut_ack_to_unacceptable_ack_close_wait";
            default:                                   return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpUnacceptable14SM, tcp_unacceptable_14)
