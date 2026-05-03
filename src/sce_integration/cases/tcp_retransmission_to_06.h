#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"

#include "tcp_retransmission_to_06_sm.h"

namespace tc8::sce::cases {

using TcpRetransmissionTo06SM =
    ::SCE::Generated::tcp_retransmission_to_06::tcp_retransmission_to_06;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpRetransmissionTo06SM>
    : TcpAnyBase<cases::TcpRetransmissionTo06SM> {
    static constexpr std::string_view kCaseId       = "TCP_RETRANSMISSION_TO_06";
    static constexpr std::string_view kSpecSection  = "4.8.6.11";
    static constexpr std::string_view kDescription  =
        "DUT TCP SHOULD use RTO = 1 sec initially (RFC 6298 §2.1).";

    // Hold-window for the deferred TesterAutoRstDrop release. Linux's
    // first SYN retransmit lands at TCP_TIMEOUT_INIT = 1 s; the SCXML
    // listening_syn_retx state has a 2.5 s deadline, so 4 s covers
    // the entire phase budget plus margin for parallel-worker
    // scheduler jitter.
    static constexpr std::chrono::milliseconds kRstDropHold{4000};

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  = static_cast<std::uint16_t>(
            kBasicsActiveLocalPort  + kTcpRetransmissionTo06LocalOffset);
        const std::uint16_t remote_port = static_cast<std::uint16_t>(
            kBasicsActiveRemotePort + kTcpRetransmissionTo06LocalOffset);

        // shared_ptr lifetime: the CLI runs `kickStimulus` synchronously
        // before the SCXML listen window opens, so a body-scoped
        // TesterAutoRstDrop dies at stimulus return — i.e. before the
        // DUT's first SYN retransmit fires (~1 s after the active
        // OPEN). Capturing the rule into a delayed scheduler lambda
        // keeps the iptables OUTPUT --tcp-flags RST,RST -j DROP rule
        // installed for the entire SCXML phase budget. Same pattern
        // PROBING_WINDOWS_03..06 use for TesterAutoAckDrop.
        auto rst_drop = std::make_shared<TesterAutoRstDrop>(cfg);

        // No tester-side listener: the DUT's SYN reaches the tester
        // kernel, which would normally RST since remote_port is
        // unbound. The TesterAutoRstDrop rule above silently swallows
        // those RSTs so the DUT stays in SYN-SENT and re-fires its
        // retransmit timer at TCP_TIMEOUT_INIT.
        sendOpenTcpSocketActiveRequest(
            cfg, iface, cfg.arp.dut_real_mac,
            /*req_id=*/1, local_port,
            cfg.ipv4.tester_ip, remote_port);

        // Defer the TesterAutoRstDrop release so the iptables rule
        // outlives both the first-SYN observation and the ~1 s wait
        // for the retransmit. Lambda owns the shared_ptr; once it
        // fires the strong ref drops and the dtor runs `iptables -D`.
        scheduler.schedule(kRstDropHold, [rst_drop]() {
            (void)rst_drop;
        });

        // No `sendCloseTcpSocketRequest`: a `closeTcpSocket` call on
        // the SYN-SENT tc8-dut socket would `shutdown(fd, SHUT_RDWR)`
        // which kicks the connect() worker out of its blocking syscall
        // by sending an RST and transitioning the kernel socket to
        // CLOSED — cancelling the very SYN-retransmit timer this case
        // observes. smoke-test's `kill_worker_procs` reaps tc8-dut
        // per case so the leaked Active socket is cleaned by SIGKILL
        // and netns teardown rather than by the upper-tester close
        // path.
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                       return "pass";
            case State::Fail_no_first_syn:          return "fail:no_dut_first_syn";
            case State::Fail_no_syn_retx:           return "fail:no_dut_syn_retransmit_within_listen_window";
            case State::Fail_rto_out_of_window:     return "fail:syn_retransmit_rto_out_of_rfc6298_window";
            default:                                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpRetransmissionTo06SM, tcp_retransmission_to_06)
