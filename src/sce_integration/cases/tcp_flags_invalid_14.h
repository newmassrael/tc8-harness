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

#include "tcp_flags_invalid_14_sm.h"

namespace tc8::sce::cases {

using TcpFlagsInvalid14SM = ::SCE::Generated::tcp_flags_invalid_14::tcp_flags_invalid_14;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpFlagsInvalid14SM>
    : TcpAnyBase<cases::TcpFlagsInvalid14SM> {
    static constexpr std::string_view kCaseId       = "TCP_FLAGS_INVALID_14";
    static constexpr std::string_view kSpecSection  = "4.8.6.6";
    static constexpr std::string_view kDescription  =
        "TCP in TIME-WAIT state MUST send an ACK with next expected "
        "SEQ number after receiving any segment with OTW SEQ number "
        "(RFC 793 §3.9 p69 Event Processing)";

    static constexpr std::array<std::uint8_t, 4> kCorruptPayload = {
        0xCAU, 0xFEU, 0xBAU, 0xBEU};

    // Two iterations:
    //   * Phase 1 — flag set = FIN.
    //   * Phase 2 — flag set = Data segment.
    //
    // Both probes carry an OTW SEQ value so the spec edge being
    // exercised is "any segment with OTW SEQ → ACK" rather than the
    // RST-on-RST or in-window paths. The flag-set distinction is
    // wire-level only; the DUT's TIME-WAIT response is an empty ACK
    // in either case (Linux's tcp_timewait_state_process resends ACK
    // for any non-RST OTW segment, regardless of whether FIN is set
    // or whether the segment carries payload).
    //
    // Per phase: driveTcpToTimeWaitFw2 walks DUT through ESTABLISHED
    // → FIN-WAIT-1 → FIN-WAIT-2 → TIME-WAIT. The helper closes the
    // tester fd before returning, freeing the (49500, 23456) quad
    // for the raw-injected probe; the captured tester snd_nxt /
    // rcv_nxt pair feeds the corrupt segment's seq / ack base.
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        // -------- Phase 1: OTW SEQ FIN in TIME-WAIT --------
        {
            const auto info = driveTcpToTimeWaitFw2(
                cfg, iface, cfg.arp.dut_real_mac,
                /*open_req_id=*/1, /*close_req_id=*/2, /*socket_id=*/1,
                kBasicsActiveLocalPort  + kTcpFlagsInvalid14Phase1LocalOffset,
                kBasicsActiveRemotePort + kTcpFlagsInvalid14Phase1LocalOffset);
            if (info.ok) {
                // tcp_timewait_state_process emits ACK with ack_num ==
                // tw_rcv_nxt == tester.snd_nxt at TW entry ==
                // info.tester_seq_post_fin. Empirically confirmed via
                // pcap 2026-05-07 (FIN-flag and data-segment OTW probes
                // both elicit the same ACK shape).
                c.expected_ack_num = info.tester_seq_post_fin;
                ::tc8::stimulus::TcpSegmentSpec probe{};
                probe.src_port = kBasicsActiveRemotePort + kTcpFlagsInvalid14Phase1LocalOffset;
                probe.dst_port = kBasicsActiveLocalPort  + kTcpFlagsInvalid14Phase1LocalOffset;
                probe.seq_num  = info.tester_seq_post_fin + kOutOfWindowSeqOffset;
                probe.ack_num  = info.tester_ack_post_fin;
                probe.flags    = ::tc8::stimulus::kTcpFlagFin
                               | ::tc8::stimulus::kTcpFlagAck;
                emitTcpFrame(cfg, iface, cfg.arp.dut_real_mac, probe,
                             /*initial_wait=*/std::chrono::milliseconds(0));
            }
            std::this_thread::sleep_for(kTcpPilotPhaseGap);
        }

        // -------- Phase 2: OTW SEQ data segment in TIME-WAIT --------
        {
            const std::uint16_t phase2_local_port  = kBasicsActiveLocalPort  + kTcpFlagsInvalid14Phase2LocalOffset;
            const std::uint16_t phase2_remote_port = kBasicsActiveRemotePort + kTcpFlagsInvalid14Phase2LocalOffset;

            const auto info = driveTcpToTimeWaitFw2(
                cfg, iface, cfg.arp.dut_real_mac,
                /*open_req_id=*/3, /*close_req_id=*/4, /*socket_id=*/2,
                phase2_local_port, phase2_remote_port);
            if (info.ok) {
                c.expected_ack_num_phase2 = info.tester_seq_post_fin;
                ::tc8::stimulus::TcpSegmentSpec probe{};
                probe.src_port = phase2_remote_port;
                probe.dst_port = phase2_local_port;
                probe.seq_num  = info.tester_seq_post_fin + kOutOfWindowSeqOffset;
                probe.ack_num  = info.tester_ack_post_fin;
                probe.flags    = ::tc8::stimulus::kTcpFlagPsh
                               | ::tc8::stimulus::kTcpFlagAck;
                probe.payload.assign(kCorruptPayload.begin(),
                                     kCorruptPayload.end());
                emitTcpFrame(cfg, iface, cfg.arp.dut_real_mac, probe,
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
            case State::Fail_p1_no_probe_ack:          return "fail:no_dut_ack_to_otw_fin_in_time_wait";
            case State::Fail_p2_no_handshake_ack:      return "fail:no_dut_handshake_ack_phase2";
            case State::Fail_p2_no_dut_fin:            return "fail:no_dut_fin_phase2";
            case State::Fail_p2_no_tester_fin_ack:     return "fail:no_dut_ack_to_tester_fin_phase2";
            case State::Fail_p2_no_probe_ack:          return "fail:no_dut_ack_to_otw_data_in_time_wait";
            default:                                   return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsInvalid14SM, tcp_flags_invalid_14)
