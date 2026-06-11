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

#include "tcp_flags_invalid_10_sm.h"

namespace tc8::sce::cases {

using TcpFlagsInvalid10SM = ::SCE::Generated::tcp_flags_invalid_10::tcp_flags_invalid_10;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpFlagsInvalid10SM>
    : TcpAnyBase<cases::TcpFlagsInvalid10SM> {
    static constexpr std::string_view kCaseId       = "TCP_FLAGS_INVALID_10";
    static constexpr std::string_view kSpecSection  = "4.8.6.6";
    static constexpr std::string_view kDescription  =
        "TCP in FIN-WAIT-2 state MUST send an ACK with next expected "
        "SEQ number after receiving any segment with OTW SEQ number "
        "(RFC 793 §3.9 p69 Event Processing). 5 spec iterations "
        "exercise flag set ∈ {SYN, SYN+ACK, ACK, FIN, data}";

    static constexpr std::array<std::uint8_t, 4> kCorruptPayload = {
        0xCAU, 0xFEU, 0xBAU, 0xBEU};

    // Per phase: independent active-OPEN handshake on its own port
    // quad → UT close drives DUT FIN → tester-kernel auto-ACK
    // (NOT suppressed) advances DUT FW1 → FW2 → 200 ms post-FIN
    // settle covers the auto-ACK round-trip + tester socket TCP
    // state stabilisation before TCP_REPAIR query → queryTcpSeqRange
    // → raw-inject CASE-distinct OTW probe → DUT empty ACK on the
    // same port quad. Same prelude as UNACCEPTABLE_10 lifted to
    // five port quads.
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

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
            sendCloseTcpSocketRequest(
                cfg, iface, cfg.dut.mac,
                close_req_id, socket_id);
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            if (tester_fd < 0) {
                std::this_thread::sleep_for(kTcpPilotPhaseGap);
                continue;
            }
            const auto seq_range = queryTcpSeqRange(tester_fd);
            if (!seq_range.has_value()) {
                std::this_thread::sleep_for(kTcpPilotPhaseGap);
                continue;
            }

            // Spec literal "ACK with next expected SEQ number" — DUT
            // challenge ACK to OTW SEQ probe carries ack_num ==
            // DUT.rcv.nxt == tester.snd_nxt at injection. Per-phase
            // slot because each phase opens a fresh active-OPEN with
            // kernel-chosen ISN_t.
            switch (phase) {
                case 0:  c.expected_ack_num        = seq_range->snd_nxt; break;
                case 1:  c.expected_ack_num_phase2 = seq_range->snd_nxt; break;
                case 2:  c.expected_ack_num_phase3 = seq_range->snd_nxt; break;
                case 3:  c.expected_ack_num_phase4 = seq_range->snd_nxt; break;
                default: c.expected_ack_num_phase5 = seq_range->snd_nxt; break;
            }
            ::tc8::stimulus::TcpSegmentSpec probe{};
            probe.src_port = remote_port;
            probe.dst_port = local_port;
            probe.seq_num  = seq_range->snd_nxt + kOutOfWindowSeqOffset;
            switch (phase) {
                case 0:  // CASE 1: SYN-only
                    probe.flags   = ::tc8::stimulus::kTcpFlagSyn;
                    probe.ack_num = 0U;
                    break;
                case 1:  // CASE 2: SYN+ACK
                    probe.flags   = ::tc8::stimulus::kTcpFlagSyn
                                  | ::tc8::stimulus::kTcpFlagAck;
                    probe.ack_num = seq_range->rcv_nxt;
                    break;
                case 2:  // CASE 3: ACK
                    probe.flags   = ::tc8::stimulus::kTcpFlagAck;
                    probe.ack_num = seq_range->rcv_nxt;
                    break;
                case 3:  // CASE 4: FIN+ACK
                    probe.flags   = ::tc8::stimulus::kTcpFlagFin
                                  | ::tc8::stimulus::kTcpFlagAck;
                    probe.ack_num = seq_range->rcv_nxt;
                    break;
                default:  // CASE 5: data segment
                    probe.flags   = ::tc8::stimulus::kTcpFlagPsh
                                  | ::tc8::stimulus::kTcpFlagAck;
                    probe.ack_num = seq_range->rcv_nxt;
                    probe.payload.assign(kCorruptPayload.begin(),
                                         kCorruptPayload.end());
                    break;
            }
            emitTcpFrame(cfg, iface, cfg.dut.mac, probe,
                         /*initial_wait=*/std::chrono::milliseconds(0));
            (void)tester_fd;
            std::this_thread::sleep_for(kTcpPilotPhaseGap);
        }
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                       return "pass";
            case State::Fail_p1_no_handshake_ack:   return "fail:no_dut_handshake_ack_phase1";
            case State::Fail_p1_no_dut_fin:         return "fail:no_dut_fin_phase1";
            case State::Fail_p1_no_probe_ack:       return "fail:no_dut_ack_to_otw_seq_syn_in_finwait2";
            case State::Fail_p2_no_handshake_ack:   return "fail:no_dut_handshake_ack_phase2";
            case State::Fail_p2_no_dut_fin:         return "fail:no_dut_fin_phase2";
            case State::Fail_p2_no_probe_ack:       return "fail:no_dut_ack_to_otw_seq_synack_in_finwait2";
            case State::Fail_p3_no_handshake_ack:   return "fail:no_dut_handshake_ack_phase3";
            case State::Fail_p3_no_dut_fin:         return "fail:no_dut_fin_phase3";
            case State::Fail_p3_no_probe_ack:       return "fail:no_dut_ack_to_otw_seq_ack_in_finwait2";
            case State::Fail_p4_no_handshake_ack:   return "fail:no_dut_handshake_ack_phase4";
            case State::Fail_p4_no_dut_fin:         return "fail:no_dut_fin_phase4";
            case State::Fail_p4_no_probe_ack:       return "fail:no_dut_ack_to_otw_seq_fin_in_finwait2";
            case State::Fail_p5_no_handshake_ack:   return "fail:no_dut_handshake_ack_phase5";
            case State::Fail_p5_no_dut_fin:         return "fail:no_dut_fin_phase5";
            case State::Fail_p5_no_probe_ack:       return "fail:no_dut_ack_to_otw_seq_data_in_finwait2";
            default:                                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsInvalid10SM, tcp_flags_invalid_10)
