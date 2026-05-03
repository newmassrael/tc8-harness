#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_flags_invalid_07_sm.h"

namespace tc8::sce::cases {

using TcpFlagsInvalid07SM = ::SCE::Generated::tcp_flags_invalid_07::tcp_flags_invalid_07;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpFlagsInvalid07SM>
    : TcpAnyBase<cases::TcpFlagsInvalid07SM> {
    static constexpr std::string_view kCaseId       = "TCP_FLAGS_INVALID_07";
    static constexpr std::string_view kSpecSection  = "4.8.6.6";
    static constexpr std::string_view kDescription  =
        "TCP in SYN-RCVD state MUST send an ACK with next expected SEQ "
        "number after receiving any segment (without RST) with OTW SEQ "
        "number and remain in the same state (RFC 793 §3.9 p69 Event "
        "Processing). 5 spec iterations exercise flag set ∈ "
        "{SYN, SYN+ACK, ACK, FIN, data}";

    static constexpr std::array<std::uint8_t, 4> kCorruptPayload = {
        0xDEU, 0xADU, 0xBEU, 0xEFU};

    // Per phase: independent passive-listener on (kBasicsListenPort+N) +
    // raw-inject SYN from (kBasicsTesterPort+N) to drive DUT into
    // SYN-RCVD + TcpFrameSnippet capture of the DUT-emitted SYN+ACK to
    // learn ISN_d + CASE-distinct OTW probe with ack_num = ISN_d + 1
    // (acceptable per RFC 793 §3.4 even though SEQ is unacceptable;
    // isolates the spec assertion to the OTW-SEQ challenge-ACK path)
    // + DUT challenge ACK observation + UT close on socket_id = N + 1.
    //
    // Function-scoped TesterAutoRstDrop covers all 5 phases: each
    // raw-inject SYN elicits a DUT SYN+ACK landing on the tester at
    // (kBasicsTesterPort+N) where no socket is bound, and the tester
    // kernel would otherwise emit auto-RST that race-kills the
    // request_sock before our OTW probe arrives. The same suppression
    // covers the tester's reception of the DUT-emitted challenge ACK,
    // since pure ACK on an unbound port also draws an auto-RST.
    //
    // CASE 4 = FIN+ACK (not bare FIN): Linux's `tcp_v4_rcv` drops bare
    // FIN at PACKET_HOST → kernel-state lookup before reaching
    // `tcp_check_req`'s OTW-SEQ branch, mirroring the §08~§13 cluster
    // convention (see project_tcp_flags_invalid_coverage memory). The
    // FIN-with-ACK shape carries a valid ack=ISN_d+1, identical to the
    // CASE 2/3/5 envelope.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        TesterAutoRstDrop rst_drop(cfg);
        (void)rst_drop;

        for (std::uint16_t phase = 0; phase < 5U; ++phase) {
            const std::uint16_t listen_port =
                static_cast<std::uint16_t>(kBasicsListenPort + phase);
            const std::uint16_t tester_port =
                static_cast<std::uint16_t>(kBasicsTesterPort + phase);
            const std::uint8_t open_req_id =
                static_cast<std::uint8_t>(1U + phase * 2U);
            const std::uint8_t close_req_id =
                static_cast<std::uint8_t>(2U + phase * 2U);
            const std::uint8_t socket_id =
                static_cast<std::uint8_t>(phase + 1U);

            sendOpenTcpSocketPassiveRequest(
                cfg, iface, cfg.arp.dut_real_mac,
                open_req_id, listen_port);
            std::this_thread::sleep_for(kTcpUtRpcWait);

            auto snippet = TcpFrameSnippet::forDutSynAck(
                cfg, iface, tester_port);

            ::tc8::stimulus::TcpSegmentSpec syn{};
            syn.src_port = tester_port;
            syn.dst_port = listen_port;
            syn.seq_num  = kTesterInitialSeq;
            syn.ack_num  = 0U;
            syn.flags    = ::tc8::stimulus::kTcpFlagSyn;
            emitTcpFrame(cfg, iface, cfg.arp.dut_real_mac, syn);

            const auto synack = snippet.tryCapture(
                std::chrono::milliseconds(500));
            if (synack.has_value()) {
                const std::uint32_t isn_d = synack->seq_num;

                ::tc8::stimulus::TcpSegmentSpec probe{};
                probe.src_port = tester_port;
                probe.dst_port = listen_port;
                probe.seq_num  =
                    kTesterInitialSeq + 1U + kOutOfWindowSeqOffset;
                switch (phase) {
                    case 0:  // CASE 1: SYN-only
                        probe.flags   = ::tc8::stimulus::kTcpFlagSyn;
                        probe.ack_num = 0U;
                        break;
                    case 1:  // CASE 2: SYN+ACK
                        probe.flags   = ::tc8::stimulus::kTcpFlagSyn
                                      | ::tc8::stimulus::kTcpFlagAck;
                        probe.ack_num = isn_d + 1U;
                        break;
                    case 2:  // CASE 3: ACK
                        probe.flags   = ::tc8::stimulus::kTcpFlagAck;
                        probe.ack_num = isn_d + 1U;
                        break;
                    case 3:  // CASE 4: FIN+ACK
                        probe.flags   = ::tc8::stimulus::kTcpFlagFin
                                      | ::tc8::stimulus::kTcpFlagAck;
                        probe.ack_num = isn_d + 1U;
                        break;
                    default:  // CASE 5: data segment (PSH+ACK + payload)
                        probe.flags   = ::tc8::stimulus::kTcpFlagPsh
                                      | ::tc8::stimulus::kTcpFlagAck;
                        probe.ack_num = isn_d + 1U;
                        probe.payload.assign(kCorruptPayload.begin(),
                                             kCorruptPayload.end());
                        break;
                }
                emitTcpFrame(cfg, iface, cfg.arp.dut_real_mac, probe,
                             /*initial_wait=*/std::chrono::milliseconds(0));
                std::this_thread::sleep_for(kTcpPilotPhaseGap);
            }

            sendCloseTcpSocketRequest(
                cfg, iface, cfg.arp.dut_real_mac,
                close_req_id, socket_id);
            std::this_thread::sleep_for(kTcpPilotPhaseGap);
        }
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                       return "pass";
            case State::Fail_p1_no_probe_ack:       return "fail:no_dut_ack_to_otw_seq_syn_in_syn_recv";
            case State::Fail_p2_no_probe_ack:       return "fail:no_dut_ack_to_otw_seq_synack_in_syn_recv";
            case State::Fail_p3_no_probe_ack:       return "fail:no_dut_ack_to_otw_seq_ack_in_syn_recv";
            case State::Fail_p4_no_probe_ack:       return "fail:no_dut_ack_to_otw_seq_fin_in_syn_recv";
            case State::Fail_p5_no_probe_ack:       return "fail:no_dut_ack_to_otw_seq_data_in_syn_recv";
            default:                                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsInvalid07SM, tcp_flags_invalid_07)
