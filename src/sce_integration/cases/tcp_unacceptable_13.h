#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_unacceptable_13_sm.h"

namespace tc8::sce::cases {

using TcpUnacceptable13SM = ::SCE::Generated::tcp_unacceptable_13::tcp_unacceptable_13;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpUnacceptable13SM>
    : TcpAnyBase<cases::TcpUnacceptable13SM> {
    static constexpr std::string_view kCaseId       = "TCP_UNACCEPTABLE_13";
    static constexpr std::string_view kSpecSection  = "4.8.6.3";
    static constexpr std::string_view kDescription  =
        "TCP in TIME-WAIT state MUST return ACK with proper SEQ and "
        "ACK numbers after receiving a segment with OTW SEQ or "
        "unacceptable ACK (RFC 793 §3.4 p37 Establishing a Connection)";

    static constexpr std::array<std::uint8_t, 4> kCorruptPayload = {
        0xCAU, 0xFEU, 0xBAU, 0xBEU};

    // Two iterations:
    //   * Phase 1 — data segment with out-of-window SEQ.
    //   * Phase 2 — data segment with unacceptable ACK number.
    //
    // Per phase: driveTcpToTimeWaitFw2 walks DUT through ESTABLISHED
    // → FIN-WAIT-1 → FIN-WAIT-2 → TIME-WAIT (handshake / UT close /
    // tester auto-ACK / tester shutdown(WR) FIN / DUT pure ACK). The
    // helper closes the tester fd before returning, so the (49500,
    // 23456) quad is wholly available to raw-injected probes; the
    // helper also captures the tester snd_nxt / rcv_nxt at TIME-WAIT
    // entry for use as the corrupt segment's seq / ack base.
    //
    // Probe construction:
    //   * Phase 1 (OTW SEQ): seq = tester_seq_post_fin +
    //                        kOutOfWindowSeqOffset; ack =
    //                        tester_ack_post_fin (acceptable).
    //   * Phase 2 (unacc ACK): seq = tester_seq_post_fin (in-window);
    //                          ack = tester_ack_post_fin +
    //                          kUnacceptableAckOffset.
    //
    // Linux's tcp_timewait_state_process emits an empty ACK in either
    // CASE — the wire-level observation is identical to UNACCEPTABLE
    // _09's per-phase probe-ACK shape (pure DUT ACK on the same
    // 4-tuple), differing only by the DUT being in TIME-WAIT instead
    // of FIN-WAIT-1.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        // -------- Phase 1: OTW SEQ in TIME-WAIT --------
        {
            const auto info = driveTcpToTimeWaitFw2(
                cfg, iface, cfg.arp.dut_real_mac,
                /*open_req_id=*/1, /*close_req_id=*/2, /*socket_id=*/1);
            if (info.ok) {
                ::tc8::stimulus::TcpSegmentSpec data{};
                data.src_port = kBasicsActiveRemotePort;
                data.dst_port = kBasicsActiveLocalPort;
                data.seq_num  = info.tester_seq_post_fin + kOutOfWindowSeqOffset;
                data.ack_num  = info.tester_ack_post_fin;
                data.flags    = ::tc8::stimulus::kTcpFlagPsh
                              | ::tc8::stimulus::kTcpFlagAck;
                data.payload.assign(kCorruptPayload.begin(),
                                    kCorruptPayload.end());
                emitTcpFrame(cfg, iface, cfg.arp.dut_real_mac, data,
                             /*initial_wait=*/std::chrono::milliseconds(0));
            }
            std::this_thread::sleep_for(kTcpPilotPhaseGap);
        }

        // -------- Phase 2: unacceptable ACK in TIME-WAIT --------
        {
            const std::uint16_t phase2_local_port  = kBasicsActiveLocalPort  + 1U;
            const std::uint16_t phase2_remote_port = kBasicsActiveRemotePort + 1U;

            const auto info = driveTcpToTimeWaitFw2(
                cfg, iface, cfg.arp.dut_real_mac,
                /*open_req_id=*/3, /*close_req_id=*/4, /*socket_id=*/2,
                phase2_local_port, phase2_remote_port);
            if (info.ok) {
                ::tc8::stimulus::TcpSegmentSpec data{};
                data.src_port = phase2_remote_port;
                data.dst_port = phase2_local_port;
                data.seq_num  = info.tester_seq_post_fin;
                data.ack_num  = info.tester_ack_post_fin + kUnacceptableAckOffset;
                data.flags    = ::tc8::stimulus::kTcpFlagPsh
                              | ::tc8::stimulus::kTcpFlagAck;
                data.payload.assign(kCorruptPayload.begin(),
                                    kCorruptPayload.end());
                emitTcpFrame(cfg, iface, cfg.arp.dut_real_mac, data,
                             /*initial_wait=*/std::chrono::milliseconds(0));
            }
            std::this_thread::sleep_for(kTcpPilotPhaseGap);
        }
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                          return "pass";
            case State::Fail_p1_no_handshake_ack:      return "fail:no_dut_handshake_ack_phase1";
            case State::Fail_p1_no_dut_fin:            return "fail:no_dut_fin_phase1";
            case State::Fail_p1_no_tester_fin_ack:     return "fail:no_dut_ack_to_tester_fin_phase1";
            case State::Fail_p1_no_probe_ack:          return "fail:no_dut_ack_to_otw_seq_in_time_wait";
            case State::Fail_p2_no_handshake_ack:      return "fail:no_dut_handshake_ack_phase2";
            case State::Fail_p2_no_dut_fin:            return "fail:no_dut_fin_phase2";
            case State::Fail_p2_no_tester_fin_ack:     return "fail:no_dut_ack_to_tester_fin_phase2";
            case State::Fail_p2_no_probe_ack:          return "fail:no_dut_ack_to_unacceptable_ack_in_time_wait";
            default:                                   return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpUnacceptable13SM, tcp_unacceptable_13)
