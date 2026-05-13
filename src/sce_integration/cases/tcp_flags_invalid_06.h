#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_flags_invalid_06_sm.h"

namespace tc8::sce::cases {

using TcpFlagsInvalid06SM = ::SCE::Generated::tcp_flags_invalid_06::tcp_flags_invalid_06;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpFlagsInvalid06SM>
    : TcpAnyBase<cases::TcpFlagsInvalid06SM> {
    static constexpr std::string_view kCaseId       = "TCP_FLAGS_INVALID_06";
    static constexpr std::string_view kSpecSection  = "4.8.6.6";
    static constexpr std::string_view kDescription  =
        "TCP in SYN-SENT state MUST drop a segment with neither SYN "
        "nor RST flag set and remain in the same state "
        "(RFC 793 §3.9 p68 Event Processing). 2 spec iterations "
        "exercise <stp> ∈ {no data, data}";

    static constexpr std::array<std::uint8_t, 4> kProbePayload = {
        0xDEU, 0xADU, 0xBEU, 0xEFU};

    // Each phase: TesterAutoRstDrop scope + active-OPEN to unbound
    // tester port + TcpFrameSnippet ISN_d learn + raw-inject ACK
    // (no SYN, no RST) with ack=ISN_d+1 (acceptable per RFC 793
    // RFC 793 §3.4 — the only value in [SND.UNA, SND.NXT] for SYN-SENT).
    // CASE 1 carries no payload; CASE 2 carries 4 bytes of data
    // exercising the spec's `<stp> = data` iteration. Linux's
    // `tcp_rcv_synsent_state_process` drops the segment without
    // emitting any response in either case (the discard fall-
    // through fires before any SYN-processing branch).
    //
    // Phase 1 fires synchronously; phase 2 schedules via
    // `scheduleAfterStateEntry(Listening_p2_dut_syn)` so its DUT
    // SYN is not queued behind phase 1's wall-clock absence. Same
    // shape as FLAGS_INVALID_05 / _15.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        runPhase1BareAck(cfg, iface);

        ::tc8::TestConfig cfg_copy = cfg;
        std::string       iface_str(iface);
        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_p2_dut_syn),
            [cfg_copy, iface_str]() {
                runPhase2AckWithPayload(cfg_copy, iface_str);
            });
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                       return "pass";
            case State::Fail_p1_no_dut_syn:         return "fail:no_dut_syn_phase1_bare_ack";
            case State::Fail_p1_unexpected_response:return "fail:dut_emitted_response_to_bare_ack_with_acceptable_ack";
            case State::Fail_p2_no_dut_syn:         return "fail:no_dut_syn_phase2_ack_with_payload";
            case State::Fail_p2_unexpected_response:return "fail:dut_emitted_response_to_ack_with_payload_acceptable_ack";
            default:                                return "running";
        }
    }

private:
    static void emitAck(const ::tc8::TestConfig& cfg,
                        std::string_view iface,
                        std::uint16_t local_port,
                        std::uint16_t remote_port,
                        std::uint32_t isn_d,
                        std::vector<std::uint8_t> payload) {
        ::tc8::stimulus::TcpSegmentSpec probe{};
        probe.src_port = remote_port;
        probe.dst_port = local_port;
        probe.seq_num  = ::tc8::sce::tcp::kTesterInitialSeq;
        probe.ack_num  = isn_d + 1U;
        probe.flags    = ::tc8::stimulus::kTcpFlagAck;
        probe.payload  = std::move(payload);
        ::tc8::sce::tcp::emitTcpFrame(cfg, iface, cfg.arp.dut_real_mac, probe,
                                      /*initial_wait=*/std::chrono::milliseconds(0));
    }

    static void runPhase1BareAck(const ::tc8::TestConfig& cfg,
                                 std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 24U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 24U;

        TesterAutoRstDrop rst_drop(cfg);
        (void)rst_drop;

        auto snippet = TcpFrameSnippet::forDutSyn(cfg, iface, local_port);

        sendOpenTcpSocketActiveRequest(
            cfg, iface, cfg.arp.dut_real_mac,
            /*req_id=*/1, local_port, cfg.ipv4.tester_ip, remote_port);

        const auto syn = snippet.tryCapture(std::chrono::milliseconds(500));
        if (syn.has_value()) {
            emitAck(cfg, iface, local_port, remote_port, syn->seq_num, {});
        }
    }

    static void runPhase2AckWithPayload(const ::tc8::TestConfig& cfg,
                                        std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 25U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 25U;

        TesterAutoRstDrop rst_drop(cfg);
        (void)rst_drop;

        auto snippet = TcpFrameSnippet::forDutSyn(cfg, iface, local_port);

        sendOpenTcpSocketActiveRequest(
            cfg, iface, cfg.arp.dut_real_mac,
            /*req_id=*/2, local_port, cfg.ipv4.tester_ip, remote_port);

        const auto syn = snippet.tryCapture(std::chrono::milliseconds(500));
        if (syn.has_value()) {
            emitAck(cfg, iface, local_port, remote_port, syn->seq_num,
                    std::vector<std::uint8_t>(kProbePayload.begin(),
                                              kProbePayload.end()));
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsInvalid06SM, tcp_flags_invalid_06)
