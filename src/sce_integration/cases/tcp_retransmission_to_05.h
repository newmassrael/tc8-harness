#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"

#include "tcp_retransmission_to_05_sm.h"

namespace tc8::sce::cases {

using TcpRetransmissionTo05SM =
    ::SCE::Generated::tcp_retransmission_to_05::tcp_retransmission_to_05;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpRetransmissionTo05SM>
    : TcpAnyBase<cases::TcpRetransmissionTo05SM> {
    static constexpr std::string_view kCaseId       = "TCP_RETRANSMISSION_TO_05";
    static constexpr std::string_view kSpecSection  = "4.8.6.11";
    static constexpr std::string_view kDescription  =
        "DUT TCP MUST include exponential backoff (more than linear) "
        "for successive RTO values for SYN segments (RFC 1122 "
        "§4.2.3.1 — RFC 6298 §5).";

    // Hold-window for the deferred TesterAutoRstDrop release. Linux's
    // SYN-retransmit sequence on TCP_TIMEOUT_INIT=1 s baseline lands
    // retx 1/2/3 at ~1 s / 3 s / 7 s post-active-OPEN. The SCXML
    // phase budget (5 + 2.5 + 3.5 + 5.5 = 16.5 s) plus the ~1.5 s
    // UT boot wait sets a comfortable 18 s envelope; 18 s for the
    // hold keeps the iptables OUTPUT --tcp-flags RST,RST -j DROP
    // rule installed for the entire observation window with margin
    // for parallel-worker scheduler jitter.
    static constexpr std::chrono::milliseconds kRstDropHold{18000};

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  = static_cast<std::uint16_t>(
            kBasicsActiveLocalPort  + kTcpRetransmissionTo05LocalOffset);
        const std::uint16_t remote_port = static_cast<std::uint16_t>(
            kBasicsActiveRemotePort + kTcpRetransmissionTo05LocalOffset);

        // shared_ptr-and-scheduler.schedule lifetime extension: the
        // RstDrop scope must outlive 4 SCXML phases (~16.5 s of
        // observation budget); see TCP_RETRANSMISSION_TO_06 for the
        // full rationale on body-scoped RAII vs deferred release.
        auto rst_drop = std::make_shared<TesterAutoRstDrop>(cfg);

        // Active OPEN to a tester endpoint with no listener. The
        // tester-kernel auto-RST is silently swallowed by the
        // iptables OUTPUT rule above, so the DUT stays in SYN-SENT
        // and the retransmit timer doubles every RTO firing per
        // RFC 6298 §5 step 5.5 — visible as 1 s / 2 s / 4 s
        // inter-frame deltas on Linux 6.x's TCP_TIMEOUT_INIT
        // baseline.
        sendOpenTcpSocketActiveRequest(
            cfg, iface, cfg.arp.dut_real_mac,
            /*req_id=*/1, local_port,
            cfg.ipv4.tester_ip, remote_port);

        scheduler.schedule(kRstDropHold, [rst_drop]() {
            (void)rst_drop;
        });

        // No `sendCloseTcpSocketRequest` for the same reason as
        // RETRANSMISSION_TO_06 — closing a SYN-SENT socket via the
        // upper-tester would `shutdown(fd, SHUT_RDWR)` and abort the
        // very retransmit sequence we observe. smoke-test's
        // per-case `kill_worker_procs` reaps tc8-dut so the leaked
        // Active socket is released by SIGKILL and netns teardown.
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                              return "pass";
            case State::Fail_no_first_syn:                 return "fail:no_dut_first_syn";
            case State::Fail_no_syn_retx_1:                return "fail:no_dut_syn_retransmit_1";
            case State::Fail_no_syn_retx_2:                return "fail:no_dut_syn_retransmit_2";
            case State::Fail_no_syn_retx_3:                return "fail:no_dut_syn_retransmit_3";
            case State::Fail_initial_rto_out_of_window:    return "fail:syn_retx1_rto_out_of_rfc6298_initial_window";
            case State::Fail_retx2_not_doubled:            return "fail:syn_retx2_delta_not_greater_than_initial_rto";
            case State::Fail_retx3_not_doubled:            return "fail:syn_retx3_delta_not_greater_than_retx2_lower_bound";
            default:                                       return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpRetransmissionTo05SM, tcp_retransmission_to_05)
