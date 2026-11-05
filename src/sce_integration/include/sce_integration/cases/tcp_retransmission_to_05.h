#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>

#include "tc8/bpf_group.h"
#include "tc8/captured_event.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/ipv4_expected.h"
#include "sce_integration/tcp_case_captured.h"
#include "sce_integration/tcp_observation.h"
#include "sce_integration/tcp_pilot_common.h"
#include "sce_integration/tcp_retransmission_series.h"
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
    static constexpr std::string_view kDescription  =
        "DUT TCP MUST include exponential backoff (more than linear) "
        "for successive RTO values for SYN segments (RFC 1122 "
        "§4.2.3.1 — RFC 6298 §5).";
    static constexpr bool             kDeprecated   = false;
    static constexpr int              kTopology     = 1;
    static constexpr ::tc8::BpfGroup  kBpfGroup     = ::tc8::BpfGroup::Tcp;

    // The verdict reads the DUT's RTO after each SYN retransmission (tcpi_rto,
    // tcpi_retransmits) — a state introspection the opcode UT exposes
    // (OpQueryTcpInfo) but the standard AUTOSAR testability protocol does not.
    // Declaring kCapTcpInfoProbe makes the CLI capability gate SKIP this case on a
    // testability backend (Tier 2 2b#4) instead of failing it. kCapTcpSynSentOpen
    // covers the non-establishing SYN-SENT open (driveSeamSynSentOpen).
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl | ::tc8::sce::kCapTcpInfoProbe |
        ::tc8::sce::kCapTcpSynSentOpen;

    using Captured = typename SM::CapturedType;
    using Expected = typename SM::ExpectedType;

    // Three retransmissions give three RTO values, the fewest that show whether the
    // steps between them grow (TcpRetransmissionSeriesCaptured).
    static constexpr std::uint8_t kRetransmissions = 3;
    static constexpr ::tc8::sce::tcp::RetransmissionWaitNames kRetransmissionWaits = {
        "dut_syn_retransmission_1", "dut_syn_retransmission_2", "dut_syn_retransmission_3"};

    // The DUT sends its SYN as soon as the active OPEN reaches it.
    static constexpr std::chrono::milliseconds kFirstSynBound{5000};

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        using namespace ::tc8::sce::tcp;

        const std::uint16_t local_port  = static_cast<std::uint16_t>(
            kBasicsActiveLocalPort  + kTcpRetransmissionTo05LocalOffset);
        const std::uint16_t remote_port = static_cast<std::uint16_t>(
            kBasicsActiveRemotePort + kTcpRetransmissionTo05LocalOffset);

        // Spec step 3 for the whole body: the tester's kernel would answer the SYN to a
        // port it serves nothing on with a RST, which ends SYN-SENT. Its RSTs are dropped
        // on egress until the stimulus returns, and the stimulus returns only once the
        // last retransmission has been seen or its window has elapsed, however long the
        // DUT's RTO makes that. Installed before the open, so the first SYN draws none.
        TesterAutoRstDrop rst_drop(cfg);

        // Spec steps 1-2: the active OPEN with no listener, and the DUT's SYN.
        const std::uint32_t dut_ip = cfg.dut.ip;
        const ::tc8::sce::ObservationCursor before_open = ctx.observer.mark();
        auto open_conn = driveSeamSynSentOpen(ctx.dut, cfg, local_port, remote_port);
        // A nullopt open is an unreachable DUT (e.g. the negative dut_iface_ip flip):
        // `ut_handshake_completed` stays false and the SCXML's first cond fires.
        if (!open_conn) return;
        const ::tc8::sce::DutSocket dut_sock = open_conn->socket;
        const auto first = ctx.observer.awaitObservation(
            "dut_syn", before_open, dutSynFrom(dut_ip, local_port), kFirstSynBound);
        if (!first) return;
        // The prelude this case needs: the DUT's active open is on the wire.
        c.ut_handshake_completed = true;

        // Spec steps 4-5: each SYN retransmission, waited for as long as the DUT's own
        // RTO says it will take, then the RTO the DUT now holds for the next one
        // (tcp_retransmission_series.h).
        watchRetransmissions(
            c, ctx, dut_sock, before_open,
            [dut_ip, local_port](std::int64_t after_ts_us) {
                return dutSynFrom(dut_ip, local_port, after_ts_us);
            },
            segmentOf(first->view()).observed_ts_us, kRetransmissions, kRetransmissionWaits);

        // No closeTcp — closing a SYN-SENT socket through the seam would shut the fd
        // down and abort the retransmissions; the harness reaps the DUT per case, which
        // releases the socket.
    }

    static void dispatch(Captured& /*c*/, SM& /*sm*/, const ::tc8::CapturedEvent& /*ev*/) {
        // The stimulus has seen every frame the verdict needs (through the observer, on
        // the case's own capture) and left the times and RTO values in `captured`; the
        // machine evaluates them on the `evaluate` it raises at entry.
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpRetransmissionTo05SM, tcp_retransmission_to_05)
