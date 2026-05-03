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

#include "tcp_flags_processing_08_sm.h"

namespace tc8::sce::cases {

using TcpFlagsProcessing08SM =
    ::SCE::Generated::tcp_flags_processing_08::tcp_flags_processing_08;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpFlagsProcessing08SM>
    : TcpAnyBase<cases::TcpFlagsProcessing08SM> {
    static constexpr std::string_view kCaseId       = "TCP_FLAGS_PROCESSING_08";
    static constexpr std::string_view kSpecSection  = "4.8.6.7";
    static constexpr std::string_view kDescription  =
        "TCP in CLOSED / LISTEN / SYN-SENT MUST not process a FIN: "
        "CLOSED replies RST, LISTEN / SYN-SENT silently drop "
        "(RFC 793 §3.9 p75 Event Processing). 3 spec iterations "
        "exercise wst ∈ {CLOSED, LISTEN, SYN-SENT}";

    // Phase 1 CLOSED + phase 2 LISTEN run synchronously in stimulus
    // body; phase 3 SYN-SENT defers to scheduleAfterStateEntry so its
    // DUT-emitted SYN is not consumed (and discarded) by SCXML's
    // phase 2 absence state. The pump loop dispatches pcap events in
    // order regardless of wall-time spacing, so a phase 3 SYN
    // emitted before SCXML reaches phase 3 listening would be drained
    // during phase 2's 3 s wall absence and the phase 3 dut_syn
    // deadline would then time out (verified empirically 2026-04-26
    // pcap dump). Same multi-phase-absence pattern as
    // FLAGS_INVALID_15 phases 2..8 + FRAGMENTS_01..04 compound.
    //
    // Phase 1 CLOSED: bare FIN to kBasicsClosedPort. Same wire shape
    // as BASICS_04 phase 2; spec demands RST(seq=0) per RFC 793 §3.9.
    //
    // Phase 2 LISTEN: passive listener on kBasicsListenPort + 14
    // (clear of FLAGS_INVALID_07's +0..+4 reservation), bare FIN
    // from kBasicsTesterPort + 71. Linux's tcp_rcv_state_process
    // LISTEN handler silently drops non-SYN segments per RFC 793
    // §3.9; SCXML absence guard catches any DUT-emitted segment on
    // the listen 4-tuple.
    //
    // Phase 3 SYN-SENT: active-OPEN on (kBasicsActiveLocalPort + 52,
    // kBasicsActiveRemotePort + 52). TesterAutoRstDrop scoped to the
    // schedule lambda — alive during the FIRST DUT SYN emission so
    // tester kernel's auto-RST to that SYN is dropped. After the
    // lambda returns RstDrop dies; the next DUT SYN retransmit (Linux
    // base RTO 1 s) draws a tester RST and DUT transitions SYN-SENT →
    // CLOSED silently (no DUT egress in that path), so the absence
    // guard remains satisfied. Bare FIN (no ACK) is silently dropped
    // by tcp_rcv_synsent_state_process; absence guard tolerates DUT
    // SYN retransmits (is_dut_syn explicitly excluded from the fail
    // predicate).
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        // Phase 1 — CLOSED state: bare FIN to closed DUT port.
        emitTcpStimulus(cfg, iface, cfg.arp.dut_real_mac,
                        /*dst_port=*/kBasicsClosedPort,
                        /*flags=*/::tc8::stimulus::kTcpFlagFin,
                        /*seq_num=*/kTesterInitialSeq,
                        /*ack_num=*/0U,
                        /*payload=*/{},
                        /*initial_wait=*/std::chrono::milliseconds(0));
        std::this_thread::sleep_for(kTcpPilotPhaseGap);

        // Phase 2 — LISTEN state: open passive listener + raw-inject
        // bare FIN from a unique tester port.
        constexpr std::uint16_t kPhase2ListenPort =
            kBasicsListenPort + 14U;
        constexpr std::uint16_t kPhase2TesterPort =
            kBasicsTesterPort + 71U;

        sendOpenTcpSocketPassiveRequest(
            cfg, iface, cfg.arp.dut_real_mac,
            /*req_id=*/1, kPhase2ListenPort);
        std::this_thread::sleep_for(kTcpUtRpcWait);

        ::tc8::stimulus::TcpSegmentSpec p2_fin{};
        p2_fin.src_port = kPhase2TesterPort;
        p2_fin.dst_port = kPhase2ListenPort;
        p2_fin.seq_num  = kTesterInitialSeq;
        p2_fin.ack_num  = 0U;
        p2_fin.flags    = ::tc8::stimulus::kTcpFlagFin;
        emitTcpFrame(cfg, iface, cfg.arp.dut_real_mac, p2_fin,
                     /*initial_wait=*/std::chrono::milliseconds(0));

        // Phase 3 — deferred via scheduleAfterStateEntry(p3_dut_syn).
        constexpr std::uint16_t kPhase3LocalPort  =
            kBasicsActiveLocalPort  + 52U;
        constexpr std::uint16_t kPhase3RemotePort =
            kBasicsActiveRemotePort + 52U;

        std::string                 iface_copy(iface);
        ::tc8::TestConfig           cfg_copy = cfg;
        std::array<std::uint8_t, 6> dut_mac  = cfg.arp.dut_real_mac;

        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_p3_dut_syn),
            [iface_copy, cfg_copy, dut_mac]() {
                TesterAutoRstDrop rst_drop(cfg_copy);
                (void)rst_drop;

                sendOpenTcpSocketActiveRequest(
                    cfg_copy, iface_copy, dut_mac,
                    /*req_id=*/3, kPhase3LocalPort,
                    cfg_copy.ipv4.tester_ip, kPhase3RemotePort);
                std::this_thread::sleep_for(kTcpUtRpcWait);

                ::tc8::stimulus::TcpSegmentSpec p3_fin{};
                p3_fin.src_port = kPhase3RemotePort;
                p3_fin.dst_port = kPhase3LocalPort;
                p3_fin.seq_num  = kTesterInitialSeq;
                p3_fin.ack_num  = 0U;
                p3_fin.flags    = ::tc8::stimulus::kTcpFlagFin;
                emitTcpFrame(cfg_copy, iface_copy, dut_mac, p3_fin,
                             /*initial_wait=*/std::chrono::milliseconds(0));
            });
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                           return "pass";
            case State::Fail_p1_no_dut_rst:             return "fail:no_dut_rst_to_fin_in_closed";
            case State::Fail_p1_wrong_seq:              return "fail:dut_rst_seq_not_zero_after_fin_in_closed";
            case State::Fail_p2_unexpected_response:    return "fail:dut_emitted_response_to_fin_in_listen";
            case State::Fail_p3_no_dut_syn:             return "fail:no_dut_syn_to_active_open_phase3";
            case State::Fail_p3_unexpected_response:    return "fail:dut_emitted_response_to_fin_in_syn_sent";
            default:                                    return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsProcessing08SM, tcp_flags_processing_08)
