#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <string_view>
#include <thread>

#include "tc8/bpf_group.h"
#include "tc8/captured_event.h"
#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/ipv4_expected.h"
#include "sce_integration/tcp_captured.h"
#include "sce_integration/tcp_pilot_common.h"
#include "sce_integration/test_case_traits.h"
#include "sce_integration/test_runner.h"

#include "tcp_retransmission_to_06_sm.h"

namespace tc8::sce::cases {

using TcpRetransmissionTo06SM =
    ::SCE::Generated::tcp_retransmission_to_06::tcp_retransmission_to_06;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpRetransmissionTo06SM> {
    using SM    = cases::TcpRetransmissionTo06SM;
    using State = SM::PolicyType::State;
    using Event = SM::PolicyType::Event;

    static constexpr std::string_view kCaseId       = "TCP_RETRANSMISSION_TO_06";
    static constexpr std::string_view kSpecSection  = "4.8.6.11";
    static constexpr std::string_view kDescription  =
        "DUT TCP SHOULD use RTO = 1 sec initially (RFC 6298 §2.1).";
    static constexpr bool             kDeprecated   = false;
    static constexpr int              kTopology     = 1;
    static constexpr ::tc8::BpfGroup  kBpfGroup     = ::tc8::BpfGroup::Tcp;

    // The verdict reads the DUT's kernel initial RTO and socket state
    // (tcpi_rto, tcpi_state) — a state introspection the opcode UT exposes
    // (OpQueryTcpInfo) but the standard AUTOSAR testability protocol does
    // not. Declaring kCapTcpStateProbe makes the CLI capability gate
    // honestly SKIP this case on a testability backend (Tier 2 2b#4)
    // instead of failing it. kCapTcpSynSentOpen additionally covers the
    // non-establishing SYN-SENT open (driveSeamSynSentOpen): the testability
    // CONNECT SP requires the handshake to establish and so cannot hold a
    // socket in SYN-SENT, while the opcode non-blocking worker can.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl | ::tc8::sce::kCapTcpStateProbe |
        ::tc8::sce::kCapTcpSynSentOpen;

    using Captured = typename SM::CapturedType;
    using Expected = typename SM::ExpectedType;

    // Poll cadence + deadline for the initial-RTO observation window.
    // Linux arms TCP_TIMEOUT_INIT (=1 s on HZ=1000) when tcp_connect()
    // hands the SYN to the IP layer; the kernel reports tcpi_rto =
    // 1 s from that moment until retx 1 fires at +1 s and doubles
    // icsk_rto. Polling at 50 ms cadence with a 2 s deadline catches
    // the SYN-SENT-and-retransmits==0 state robustly even under
    // workers=4 CPU saturation (which delays the connect()-worker
    // thread by ~100-300 ms in observed worst cases).
    static constexpr std::chrono::milliseconds kPollInterval{50};
    static constexpr std::chrono::milliseconds kPhase1Deadline{2000};

    // Hold-window for the deferred TesterAutoRstDrop release. The
    // initial-RTO snapshot phase budget is 2 s; 5 s covers it with
    // margin so the iptables OUTPUT --tcp-flags RST,RST -j DROP rule
    // outlives every observation under parallel-worker scheduler
    // jitter.
    static constexpr std::chrono::milliseconds kRstDropHold{5000};

    // Wire state encoding comes from the protocol SSOT
    // (upper_tester_protocol.h kTcpStateSynSent); the SCXML cond pins
    // the value numerically — frozen wire ABI, documented there.

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view /*iface*/,
                         ::tc8::sce::IDutControl& dut,
                         IStimulusScheduler& scheduler) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  = static_cast<std::uint16_t>(
            kBasicsActiveLocalPort  + kTcpRetransmissionTo06LocalOffset);
        const std::uint16_t remote_port = static_cast<std::uint16_t>(
            kBasicsActiveRemotePort + kTcpRetransmissionTo06LocalOffset);

        // Tester-kernel auto-RST suppression must outlive both the
        // active open round-trip and the entire polling loop — a
        // body-scoped RAII would dtor before the deferred scheduler
        // lambda's wait, racing the rule install against retx fire.
        // shared_ptr captured by a delayed scheduler.schedule callback
        // is the standard §4.8 long-hold idiom (see also _05 and
        // PROBING_WINDOWS_03..06). Installed BEFORE the active open so
        // the DUT's first SYN never draws a closed-port RST.
        auto rst_drop = std::make_shared<TesterAutoRstDrop>(cfg);

        // Active OPEN routed through the backend-agnostic seam, no tester
        // listener — the SYN goes unanswered so the DUT stays in SYN-SENT,
        // which is the initial-RTO window this case observes.
        auto open_conn = driveSeamSynSentOpen(dut, cfg, local_port, remote_port);

        scheduler.schedule(kRstDropHold, [rst_drop]() {
            (void)rst_drop;
        });

        // A nullopt open is an unreachable DUT (e.g. the negative
        // dut_iface_ip flip): nothing to probe → ut_handshake_completed
        // stays false → SCXML verdicts fail_handshake_did_not_complete.
        if (!open_conn) return;
        const ::tc8::sce::DutSocket dut_sock = open_conn->socket;

        // Phase 1: poll until the first valid snapshot showing
        // state == TCP_SYN_SENT AND retransmits == 0. This is the
        // initial-RTO observation window — `tcpi_rto` here is the
        // value the kernel will count down before firing retx 1, i.e.
        // RFC 6298 §2.1's initial RTO. Exit conditions:
        //   * state==SYN_SENT && retransmits==0 → success, capture
        //   * retransmits>=1 → too late, the kernel already doubled
        //     icsk_rto; let the SCXML verdict on the missed window
        //   * deadline → no observation made; ut_handshake_completed
        //     stays false → fail_handshake_did_not_complete
        // Transient probe failures (`probe == nullopt`) retry within
        // the deadline rather than aborting — a single dropped probe
        // response under workers=4 CPU saturation must not collapse
        // the verdict when the next poll 50 ms later would succeed.
        const auto phase1_start = std::chrono::steady_clock::now();
        ::tc8::sce::DutTcpInfo p1{};
        bool p1_valid = false;
        while (true) {
            std::this_thread::sleep_for(kPollInterval);
            const auto probe = dut.tcpStateProbe()->queryInfo(dut_sock);
            if (probe) {
                p1 = *probe;
                p1_valid = true;
                if (p1.state == ::tc8::ut::kTcpStateSynSent &&
                    p1.retransmits == 0U) {
                    c.ut_handshake_completed = true;
                    break;
                }
                if (p1.retransmits >= 1U) break;
            }
            if (std::chrono::steady_clock::now() - phase1_start >= kPhase1Deadline) break;
        }
        c.ut_tcpi_p1_valid       = p1_valid;
        c.ut_tcpi_p1_state       = p1.state;
        c.ut_tcpi_p1_rto_us      = p1.rto_us;
        c.ut_tcpi_p1_retransmits = p1.retransmits;
        c.ut_tcpi_p1_unacked     = p1.unacked;

        // No closeTcp — closing a SYN-SENT socket through the seam would
        // shutdown the fd and abort the very retransmit sequence we're
        // observing. smoke-test's per-case kill_worker_procs reaps the
        // DUT so the leaked socket is released by SIGKILL and netns
        // teardown.
    }

    static void dispatch(Captured& /*c*/, SM& /*sm*/, const ::tc8::CapturedEvent& /*ev*/) {
        // Verdict is computed from kernel-side TCP_INFO snapshots
        // populated synchronously in `stimulus()`; wire frames are
        // not consulted. SM advances on the `<send event="evaluate"
        // delay="0ms"/>` raise in the initial state's onentry.
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                              return "pass";
            case State::Fail_handshake_did_not_complete:   return "fail:dut_handshake_did_not_complete";
            case State::Fail_phase1_query_failed:          return "fail:phase1_tcp_info_query_failed";
            case State::Fail_socket_not_syn_sent:          return "fail:socket_state_not_syn_sent";
            case State::Fail_initial_window_missed:        return "fail:initial_rto_window_missed_retransmit_already_fired";
            case State::Fail_initial_rto_out_of_window:    return "fail:initial_rto_out_of_rfc6298_window";
            default:                                       return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpRetransmissionTo06SM, tcp_retransmission_to_06)
