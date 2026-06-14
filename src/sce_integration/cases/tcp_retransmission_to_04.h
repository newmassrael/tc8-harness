#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <unistd.h>

#include "tc8/bpf_group.h"
#include "tc8/captured_event.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam_active_open.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/ipv4_expected.h"
#include "sce_integration/tcp_captured.h"
#include "sce_integration/tcp_pilot_common.h"
#include "sce_integration/test_case_traits.h"
#include "sce_integration/test_runner.h"

#include "tcp_retransmission_to_04_sm.h"

namespace tc8::sce::cases {

using TcpRetransmissionTo04SM =
    ::SCE::Generated::tcp_retransmission_to_04::tcp_retransmission_to_04;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpRetransmissionTo04SM> {
    using SM    = cases::TcpRetransmissionTo04SM;
    using State = SM::PolicyType::State;
    using Event = SM::PolicyType::Event;

    static constexpr std::string_view kCaseId       = "TCP_RETRANSMISSION_TO_04";
    static constexpr std::string_view kSpecSection  = "4.8.6.11";
    static constexpr std::string_view kDescription  =
        "DUT TCP MUST include exponential backoff (more than linear) "
        "for successive RTO values for data segments (RFC 1122 "
        "§4.2.3.1 — RFC 6298 §5).";
    static constexpr bool             kDeprecated   = false;
    static constexpr int              kTopology     = 1;
    static constexpr ::tc8::BpfGroup  kBpfGroup     = ::tc8::BpfGroup::Tcp;

    // The verdict reads the DUT's kernel RTO/retransmit counters across
    // three retransmissions (tcpi_rto, tcpi_retransmits) — a state
    // introspection the opcode UT exposes (OpQueryTcpInfo) but the
    // standard AUTOSAR testability protocol does not. Declaring
    // kCapTcpStateProbe makes the CLI capability gate honestly SKIP this
    // case on a testability backend (Tier 2 2b#4) instead of failing it;
    // kCapTcpControl covers the active open + data send themselves.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl | ::tc8::sce::kCapTcpStateProbe;

    using Captured = typename SM::CapturedType;
    using Expected = typename SM::ExpectedType;

    // Single 8 B data segment is enough to exercise
    // `tcp_retransmit_timer`'s exponential-backoff branch — Nagle and
    // MSS are irrelevant at this size. Distinct first byte aids pcap
    // visual inspection during regression diagnosis.
    static constexpr std::array<std::uint8_t, 8> kSegPayload = {
        'P','4','D','a','t','a','0','1'};

    // Combined-poll cadence with per-phase deadline reset. Linux's
    // data-RTO sequence on a fresh local-veth ESTABLISHED socket
    // lands retx 1/2/3 at ~200 / 600 / 1400 ms post-seg1 (RTO_MIN=200
    // ms doubling each fire). Under self-hosted CI workers=4 CPU
    // saturation the kernel's high-resolution retx timer fires can
    // drift severely — runs 25631103237 / 25629911035 saw retx 1
    // miss a 2 s deadline (`fail:no_dut_data_retransmit_1`); run
    // 25722823092 saw retx 2 miss a 3 s sequential deadline
    // (`fail:no_dut_data_retransmit_2`); the earlier single-budget
    // refactor (8 s total) saw retx 3 miss in run 25725732851
    // (`fail:phase3_tcp_info_query_failed`). All three failures
    // share a common shape — one retx phase stalls past the
    // window we allotted for it. Per-phase reset gives EACH
    // subsequent retx its own 8 s envelope measured from the prior
    // capture, so a single slow phase doesn't burn budget allocated
    // to later phases. The absolute cap kAbsoluteDeadline (25 s)
    // bounds total wall-time so a wedged DUT cannot hang the case
    // forever. Each snapshot is captured ONCE at first observation
    // of the corresponding `retransmits` threshold; fast polling at
    // 50 ms cadence keeps the retx 1 → 2 → 3 boundaries crisp so
    // strict-growth on `tcpi_rto` is preserved.
    static constexpr std::chrono::milliseconds kPollInterval{50};
    static constexpr std::chrono::milliseconds kPerPhaseDeadline{8000};
    static constexpr std::chrono::milliseconds kAbsoluteDeadline{25000};

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view /*iface*/,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  =
            kBasicsActiveLocalPort  + kTcpRetransmissionTo04LocalOffset;
        const std::uint16_t remote_port =
            kBasicsActiveRemotePort + kTcpRetransmissionTo04LocalOffset;

        // Active OPEN → ESTABLISHED routed through the backend-agnostic
        // seam (CREATE_AND_BIND + CONNECT against the tester-side
        // listener). queryTcpSeqRange on the accepted tester fd doubles
        // as the prelude-success gate before the SCXML first cond.
        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0) return;

        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (!seq_range.has_value() || !open.conn) {
            ::close(tester_fd);
            return;
        }
        const ::tc8::sce::DutSocket dut_sock = open.conn->socket;

        // Prelude success — the SCXML's first cond gates on this so a
        // negative IP-flip variant lands on
        // `fail_handshake_did_not_complete` instead of the indirect
        // `fail_phase1_query_failed`.
        c.ut_handshake_completed = true;

        // Tester-kernel auto-ACK suppression must outlive every retx
        // observation; RAII over the full stimulus body keeps it
        // active across the three poll loops. Released on stimulus
        // return, which only happens AFTER the third snapshot lands.
        TesterAutoAckDrop ack_drop(cfg);

        // Spec step 2-3: data SEND → DUT data segment 1. With ack_drop
        // active the tester kernel's auto-ACK is silently dropped on
        // egress; DUT snd_una stays at seg_seq, the retransmit timer
        // fires when icsk_rto elapses, and `tcp_retransmit_timer`
        // takes the "Use normal (exponential) backoff" branch on every
        // fire (state == TCP_ESTABLISHED — `tcp_syn_linear_timeouts`
        // applies only to TCP_SYN_SENT, see
        // [[linux-syn-data-rto-deviations]]).
        seamSendTcp(dut, dut_sock, kSegPayload);

        // Combined poll loop with per-phase deadline reset.
        // `phase_anchor` resets to `now()` each time a new phase
        // captures, so retx 2 has 8 s from retx 1 capture (not from
        // poll start), and retx 3 has 8 s from retx 2 capture. This
        // absorbs correlated CI hrtimer drift — if all three retx
        // events are individually slow, each gets its own 8 s budget.
        // `kAbsoluteDeadline` caps total wall-time so a wedged DUT
        // cannot hang forever. Transient seam-probe failures
        // (`probe == nullopt`) retry rather than abort, mirroring
        // the _05/_06 retry-on-invalid pattern.
        const auto poll_start = std::chrono::steady_clock::now();
        auto phase_anchor = poll_start;
        ::tc8::sce::DutTcpInfo p1{}, p2{}, p3{};
        bool p1_valid = false, p2_valid = false, p3_valid = false;
        while (true) {
            std::this_thread::sleep_for(kPollInterval);
            const auto probe = dut.tcpStateProbe()->queryInfo(dut_sock);
            const auto now = std::chrono::steady_clock::now();
            if (probe) {
                if (!p1_valid && probe->retransmits >= 1) {
                    p1 = *probe;
                    p1_valid = true;
                    phase_anchor = now;
                }
                if (!p2_valid && probe->retransmits >= 2) {
                    p2 = *probe;
                    p2_valid = true;
                    phase_anchor = now;
                }
                if (!p3_valid && probe->retransmits >= 3) {
                    p3 = *probe;
                    p3_valid = true;
                    break;
                }
            }
            if (now - phase_anchor >= kPerPhaseDeadline) break;
            if (now - poll_start >= kAbsoluteDeadline) break;
        }
        c.ut_tcpi_p1_valid       = p1_valid;
        c.ut_tcpi_p1_state       = p1.state;
        c.ut_tcpi_p1_rto_us      = p1.rto_us;
        c.ut_tcpi_p1_retransmits = p1.retransmits;
        c.ut_tcpi_p1_unacked     = p1.unacked;

        c.ut_tcpi_p2_valid       = p2_valid;
        c.ut_tcpi_p2_state       = p2.state;
        c.ut_tcpi_p2_rto_us      = p2.rto_us;
        c.ut_tcpi_p2_retransmits = p2.retransmits;
        c.ut_tcpi_p2_unacked     = p2.unacked;

        c.ut_tcpi_p3_valid       = p3_valid;
        c.ut_tcpi_p3_state       = p3.state;
        c.ut_tcpi_p3_rto_us      = p3.rto_us;
        c.ut_tcpi_p3_retransmits = p3.retransmits;
        c.ut_tcpi_p3_unacked     = p3.unacked;

        (void)tester_fd;
    }

    static void dispatch(Captured& /*c*/, SM& /*sm*/, const ::tc8::CapturedEvent& /*ev*/) {
        // Verdict is computed from kernel-side TCP_INFO snapshots
        // populated synchronously in `stimulus()` — wire frames are
        // not consulted, so frame ingress is intentionally a no-op.
        // The SM advances purely on the `<send event="evaluate"
        // delay="0ms"/>` raise in `<onentry>` of the initial state.
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                              return "pass";
            case State::Fail_handshake_did_not_complete:   return "fail:dut_handshake_did_not_complete";
            case State::Fail_phase1_query_failed:          return "fail:phase1_tcp_info_query_failed";
            case State::Fail_phase2_query_failed:          return "fail:phase2_tcp_info_query_failed";
            case State::Fail_phase3_query_failed:          return "fail:phase3_tcp_info_query_failed";
            case State::Fail_no_retx_1:                    return "fail:no_dut_data_retransmit_1";
            case State::Fail_no_retx_2:                    return "fail:no_dut_data_retransmit_2";
            case State::Fail_no_retx_3:                    return "fail:no_dut_data_retransmit_3";
            case State::Fail_initial_rto_not_doubled:      return "fail:phase1_rto_below_doubled_baseline";
            case State::Fail_retx2_not_doubled:            return "fail:phase2_rto_not_greater_than_phase1";
            case State::Fail_retx3_not_doubled:            return "fail:phase3_rto_not_greater_than_phase2";
            default:                                       return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpRetransmissionTo04SM, tcp_retransmission_to_04)
