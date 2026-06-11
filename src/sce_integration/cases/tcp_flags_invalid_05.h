#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_flags_invalid_05_sm.h"

namespace tc8::sce::cases {

using TcpFlagsInvalid05SM = ::SCE::Generated::tcp_flags_invalid_05::tcp_flags_invalid_05;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpFlagsInvalid05SM>
    : TcpAnyBase<cases::TcpFlagsInvalid05SM> {
    static constexpr std::string_view kCaseId       = "TCP_FLAGS_INVALID_05";
    static constexpr std::string_view kSpecSection  = "4.8.6.6";
    static constexpr std::string_view kDescription  =
        "TCP in SYN-SENT state MUST move on to CLOSED state after "
        "receiving a segment with ACK and RST and acceptable ACK "
        "number (RFC 793 §3.9 p67 Event Processing). 2 spec "
        "iterations exercise flag set ∈ {SYN+ACK, ACK} alongside RST";

    // Each phase: TesterAutoRstDrop scope + active-OPEN to unbound
    // tester port + TcpFrameSnippet ISN_d learn + raw-inject RST with
    // ack=ISN_d+1 (acceptable, the only value in [SND.UNA, SND.NXT]
    // for SYN-SENT). CASE 1's probe carries SYN+ACK+RST; CASE 2's
    // carries ACK+RST. Linux's `tcp_rcv_synsent_state_process`
    // accepts the ACK then enters the RST branch and calls
    // `tcp_done(sk)` which transitions the socket to CLOSED and
    // cancels the SYN retransmit timer — observable on the wire as
    // absence of further DUT SYN retransmits in the 3 s window.
    //
    // Phase 1 fires synchronously; phase 2 schedules via
    // `scheduleAfterStateEntry(Listening_p2_dut_syn)` so its DUT SYN
    // is not queued behind phase 1's wall-clock absence. Same shape
    // as FLAGS_INVALID_15 phases 2..8.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        runPhase1SynAckRst(cfg, iface);

        ::tc8::TestConfig cfg_copy = cfg;
        std::string       iface_str(iface);
        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_p2_dut_syn),
            [cfg_copy, iface_str]() {
                runPhase2AckRst(cfg_copy, iface_str);
            });
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                       return "pass";
            case State::Fail_p1_no_dut_syn:         return "fail:no_dut_syn_phase1_syn_ack_rst";
            case State::Fail_p1_dut_continued:      return "fail:dut_did_not_close_on_syn_ack_rst_with_acceptable_ack";
            case State::Fail_p2_no_dut_syn:         return "fail:no_dut_syn_phase2_ack_rst";
            case State::Fail_p2_dut_continued:      return "fail:dut_did_not_close_on_ack_rst_with_acceptable_ack";
            default:                                return "running";
        }
    }

private:
    static void emitRstWithFlags(const ::tc8::TestConfig& cfg,
                                 std::string_view iface,
                                 std::uint16_t local_port,
                                 std::uint16_t remote_port,
                                 std::uint32_t isn_d,
                                 std::uint8_t  flags) {
        ::tc8::stimulus::TcpSegmentSpec probe{};
        probe.src_port = remote_port;
        probe.dst_port = local_port;
        probe.seq_num  = ::tc8::sce::tcp::kTesterInitialSeq;
        probe.ack_num  = isn_d + 1U;
        probe.flags    = flags;
        ::tc8::sce::tcp::emitTcpFrame(cfg, iface, cfg.dut.mac, probe,
                                      /*initial_wait=*/std::chrono::milliseconds(0));
    }

    static void runPhase1SynAckRst(const ::tc8::TestConfig& cfg,
                                   std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 22U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 22U;

        TesterAutoRstDrop rst_drop(cfg);
        (void)rst_drop;

        auto snippet = TcpFrameSnippet::forDutSyn(cfg, iface, local_port);

        sendOpenTcpSocketActiveRequest(
            cfg, iface, cfg.dut.mac,
            /*req_id=*/1, local_port, cfg.ipv4.tester_ip, remote_port);

        const auto syn = snippet.tryCapture(std::chrono::milliseconds(500));
        if (syn.has_value()) {
            emitRstWithFlags(cfg, iface, local_port, remote_port,
                             syn->seq_num,
                             ::tc8::stimulus::kTcpFlagSyn
                                 | ::tc8::stimulus::kTcpFlagAck
                                 | ::tc8::stimulus::kTcpFlagRst);
        }
    }

    static void runPhase2AckRst(const ::tc8::TestConfig& cfg,
                                std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 23U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 23U;

        TesterAutoRstDrop rst_drop(cfg);
        (void)rst_drop;

        auto snippet = TcpFrameSnippet::forDutSyn(cfg, iface, local_port);

        sendOpenTcpSocketActiveRequest(
            cfg, iface, cfg.dut.mac,
            /*req_id=*/2, local_port, cfg.ipv4.tester_ip, remote_port);

        const auto syn = snippet.tryCapture(std::chrono::milliseconds(500));
        if (syn.has_value()) {
            emitRstWithFlags(cfg, iface, local_port, remote_port,
                             syn->seq_num,
                             ::tc8::stimulus::kTcpFlagAck
                                 | ::tc8::stimulus::kTcpFlagRst);
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsInvalid05SM, tcp_flags_invalid_05)
