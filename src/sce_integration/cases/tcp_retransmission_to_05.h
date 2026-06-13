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
#include "sce_integration/cases/_tcp_seam_active_open.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/ipv4_expected.h"
#include "sce_integration/tcp_captured.h"
#include "sce_integration/tcp_pilot_common.h"
#include "sce_integration/test_case_traits.h"
#include "sce_integration/test_runner.h"

#include "tcp_retransmission_to_05_sm.h"

namespace tc8::sce::cases {

using TcpRetransmissionTo05SM =
    ::SCE::Generated::tcp_retransmission_to_05::tcp_retransmission_to_05;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpRetransmissionTo05SM> {
    using SM    = cases::TcpRetransmissionTo05SM;
    using State = SM::PolicyType::State;
    using Event = SM::PolicyType::Event;

    static constexpr std::string_view kCaseId       = "TCP_RETRANSMISSION_TO_05";
    static constexpr std::string_view kSpecSection  = "4.8.6.11";
    static constexpr std::string_view kDescription  =
        "DUT TCP MUST include exponential backoff (more than linear) "
        "for successive RTO values for SYN segments (RFC 1122 "
        "§4.2.3.1 — RFC 6298 §5).";
    static constexpr bool             kDeprecated   = false;
    static constexpr int              kTopology     = 1;
    static constexpr ::tc8::BpfGroup  kBpfGroup     = ::tc8::BpfGroup::Tcp;

    // The verdict reads the DUT's kernel SYN-RTO/retransmit counters
    // across three retransmissions (tcpi_rto, tcpi_retransmits) — a state
    // introspection the opcode UT exposes (OpQueryTcpInfo) but the
    // standard AUTOSAR testability protocol does not. Declaring
    // kCapTcpStateProbe makes the CLI capability gate honestly SKIP this
    // case on a testability backend (Tier 2 2b#4) instead of failing it;
    // kCapTcpControl covers the active open itself.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl | ::tc8::sce::kCapTcpStateProbe;

    using Captured = typename SM::CapturedType;
    using Expected = typename SM::ExpectedType;

    // Per-phase TCP_INFO poll cadence + deadlines. Linux's SYN-side
    // retx sequence on a fresh socket with `tcp_syn_linear_timeouts=0`
    // (smoke-test sysctl override): initial RTO 1 s, retx 1 at +1 s
    // (icsk_rto doubles 1 s → 2 s), retx 2 at +2 s (2 s → 4 s), retx 3
    // at +4 s (4 s → 8 s). Total wall-clock to retx 3 ≈ 7 s. Per-phase
    // deadlines scale with the doubling pattern so a slow retx 3
    // doesn't time-budget on the SYN-emit envelope.
    static constexpr std::chrono::milliseconds kPollInterval{50};
    static constexpr std::chrono::milliseconds kSynSentProbeDeadline{2000};
    static constexpr std::chrono::milliseconds kPhase1Deadline{2000};
    static constexpr std::chrono::milliseconds kPhase2Deadline{4000};
    static constexpr std::chrono::milliseconds kPhase3Deadline{8000};

    // Hold-window for the deferred TesterAutoRstDrop release. The
    // observation budget is SYN-SENT probe (2 s) + retx 1 (2 s) +
    // retx 2 (4 s) + retx 3 (8 s) = 16 s nominal. 20 s envelope keeps
    // the iptables OUTPUT --tcp-flags RST,RST -j DROP rule installed
    // across the entire window with margin for parallel-worker
    // scheduler jitter.
    static constexpr std::chrono::milliseconds kRstDropHold{20000};

    // tcpi_state == TCP_SYN_SENT comes from the protocol SSOT
    // (upper_tester_protocol.h kTcpStateSynSent), shared with _06.

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view /*iface*/,
                         ::tc8::sce::IDutControl& dut,
                         IStimulusScheduler& scheduler) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  = static_cast<std::uint16_t>(
            kBasicsActiveLocalPort  + kTcpRetransmissionTo05LocalOffset);
        const std::uint16_t remote_port = static_cast<std::uint16_t>(
            kBasicsActiveRemotePort + kTcpRetransmissionTo05LocalOffset);

        // Tester-kernel auto-RST suppression must outlive every retx
        // observation across the 16 s envelope; shared_ptr captured by
        // a delayed scheduler.schedule lambda keeps the rule alive
        // past stimulus return (a body-scoped RAII would dtor before
        // the kernel fires retx 1, racing the SYN-SENT-stay path).
        // Installed BEFORE the active open so the DUT's first SYN never
        // draws a closed-port RST from the tester kernel.
        auto rst_drop = std::make_shared<TesterAutoRstDrop>(cfg);

        // Active OPEN routed through the backend-agnostic seam, no tester
        // listener — the SYN goes unanswered so the DUT stays in SYN-SENT
        // and retransmits, which is what this case observes.
        auto open_conn = driveSeamSynSentOpen(dut, cfg, local_port, remote_port);

        scheduler.schedule(kRstDropHold, [rst_drop]() {
            (void)rst_drop;
        });

        // A nullopt open is an unreachable DUT (e.g. the negative
        // dut_iface_ip flip): nothing to probe → ut_handshake_completed
        // stays false → SCXML verdicts fail_handshake_did_not_complete.
        if (!open_conn) return;
        const ::tc8::sce::DutSocket dut_sock = open_conn->socket;

        // SYN-SENT probe: poll until the kernel reports
        // state == TCP_SYN_SENT — this proves the DUT-side active open
        // is on the wire. Sets ut_handshake_completed under the same
        // semantic _03/_04 use (DUT reached the spec-mandated prelude
        // state). Doubles as the negative-flip detector: an unreachable
        // DUT leaves every probe invalid → flag stays false → SCXML's
        // first cond verdicts fail_handshake_did_not_complete.
        const auto probe_start = std::chrono::steady_clock::now();
        while (true) {
            std::this_thread::sleep_for(kPollInterval);
            const auto probe = dut.tcpStateProbe()->queryInfo(dut_sock);
            if (!probe) {
                if (std::chrono::steady_clock::now() - probe_start >= kSynSentProbeDeadline) break;
                continue;
            }
            if (probe->state == ::tc8::ut::kTcpStateSynSent) {
                c.ut_handshake_completed = true;
                break;
            }
            if (std::chrono::steady_clock::now() - probe_start >= kSynSentProbeDeadline) break;
        }
        if (!c.ut_handshake_completed) return;

        // Phase 1: poll until kernel confirms retx 1 fired
        // (tcpi_retransmits >= 1). After this, tcpi_rto reflects the
        // doubled value Linux installed when tcp_retransmit_timer
        // re-armed — RFC 6298 §5 step 5.5 "Set RTO <- RTO * 2."
        // Transient probe failures (`probe == nullopt`) retry within
        // the deadline budget rather than aborting the phase — a
        // single dropped probe response under workers=4 CPU saturation
        // must not collapse the verdict to phase1_query_failed when
        // the next poll 50 ms later would have succeeded.
        const auto phase1_start = std::chrono::steady_clock::now();
        ::tc8::sce::DutTcpInfo p1{};
        bool p1_valid = false;
        while (true) {
            std::this_thread::sleep_for(kPollInterval);
            const auto probe = dut.tcpStateProbe()->queryInfo(dut_sock);
            if (probe) {
                p1 = *probe;
                p1_valid = true;
                if (p1.retransmits >= 1) break;
            }
            if (std::chrono::steady_clock::now() - phase1_start >= kPhase1Deadline) break;
        }
        c.ut_tcpi_p1_valid       = p1_valid;
        c.ut_tcpi_p1_state       = p1.state;
        c.ut_tcpi_p1_rto_us      = p1.rto_us;
        c.ut_tcpi_p1_retransmits = p1.retransmits;
        c.ut_tcpi_p1_unacked     = p1.unacked;

        // Phase 2: poll until retx 2 fires. Per RFC 6298 §5 step 5.5,
        // tcpi_rto MUST exceed the phase-1 value. A linear DUT would
        // leave p2.rto_us == p1.rto_us; the SCXML's strict-growth
        // cond rejects it.
        const auto phase2_start = std::chrono::steady_clock::now();
        ::tc8::sce::DutTcpInfo p2{};
        bool p2_valid = false;
        while (true) {
            std::this_thread::sleep_for(kPollInterval);
            const auto probe = dut.tcpStateProbe()->queryInfo(dut_sock);
            if (probe) {
                p2 = *probe;
                p2_valid = true;
                if (p2.retransmits >= 2) break;
            }
            if (std::chrono::steady_clock::now() - phase2_start >= kPhase2Deadline) break;
        }
        c.ut_tcpi_p2_valid       = p2_valid;
        c.ut_tcpi_p2_state       = p2.state;
        c.ut_tcpi_p2_rto_us      = p2.rto_us;
        c.ut_tcpi_p2_retransmits = p2.retransmits;
        c.ut_tcpi_p2_unacked     = p2.unacked;

        // Phase 3: poll until retx 3 fires. Same strict-growth
        // assertion: p3.rto_us > p2.rto_us proves the kernel doubled
        // icsk_rto a third time. Three observations of strict growth
        // pin the "more than linear" RFC 1122 §4.2.3.1 MUST.
        const auto phase3_start = std::chrono::steady_clock::now();
        ::tc8::sce::DutTcpInfo p3{};
        bool p3_valid = false;
        while (true) {
            std::this_thread::sleep_for(kPollInterval);
            const auto probe = dut.tcpStateProbe()->queryInfo(dut_sock);
            if (probe) {
                p3 = *probe;
                p3_valid = true;
                if (p3.retransmits >= 3) break;
            }
            if (std::chrono::steady_clock::now() - phase3_start >= kPhase3Deadline) break;
        }
        c.ut_tcpi_p3_valid       = p3_valid;
        c.ut_tcpi_p3_state       = p3.state;
        c.ut_tcpi_p3_rto_us      = p3.rto_us;
        c.ut_tcpi_p3_retransmits = p3.retransmits;
        c.ut_tcpi_p3_unacked     = p3.unacked;

        // No closeTcp — closing a SYN-SENT socket through the seam would
        // shutdown the fd and abort the retransmit sequence. smoke-test's
        // kill_worker_procs reaps the DUT so the leaked socket is released
        // by SIGKILL and netns teardown.
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
            case State::Fail_phase2_query_failed:          return "fail:phase2_tcp_info_query_failed";
            case State::Fail_phase3_query_failed:          return "fail:phase3_tcp_info_query_failed";
            case State::Fail_no_syn_retx_1:                return "fail:no_dut_syn_retransmit_1";
            case State::Fail_no_syn_retx_2:                return "fail:no_dut_syn_retransmit_2";
            case State::Fail_no_syn_retx_3:                return "fail:no_dut_syn_retransmit_3";
            case State::Fail_initial_rto_not_doubled:      return "fail:phase1_rto_below_doubled_baseline";
            case State::Fail_retx2_not_doubled:            return "fail:phase2_rto_not_greater_than_phase1";
            case State::Fail_retx3_not_doubled:            return "fail:phase3_rto_not_greater_than_phase2";
            default:                                       return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpRetransmissionTo05SM, tcp_retransmission_to_05)
