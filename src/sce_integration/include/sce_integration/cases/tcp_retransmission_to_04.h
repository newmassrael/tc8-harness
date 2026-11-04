#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string_view>
#include <thread>
#include <unistd.h>

#include "tc8/bpf_group.h"
#include "tc8/captured_event.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/ipv4_expected.h"
#include "sce_integration/tcp_case_captured.h"
#include "sce_integration/tcp_observation.h"
#include "sce_integration/tcp_pilot_common.h"
#include "sce_integration/tcp_retransmission_timing.h"
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
    static constexpr std::string_view kDescription  =
        "DUT TCP MUST include exponential backoff (more than linear) "
        "for successive RTO values for data segments (RFC 1122 "
        "§4.2.3.1 — RFC 6298 §5).";
    static constexpr bool             kDeprecated   = false;
    static constexpr int              kTopology     = 1;
    static constexpr ::tc8::BpfGroup  kBpfGroup     = ::tc8::BpfGroup::Tcp;

    // The verdict reads the DUT's RTO after each retransmission (tcpi_rto,
    // tcpi_retransmits) — a state introspection the opcode UT exposes
    // (OpQueryTcpInfo) but the standard AUTOSAR testability protocol does not.
    // Declaring kCapTcpInfoProbe makes the CLI capability gate SKIP this case on a
    // testability backend (Tier 2 2b#4) instead of failing it; kCapTcpControl covers
    // the active open and the data send.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl | ::tc8::sce::kCapTcpInfoProbe;

    using Captured = typename SM::CapturedType;
    using Expected = typename SM::ExpectedType;

    // One 8 B data segment exercises the data-retransmission backoff; Nagle and MSS
    // play no part at this size. The distinct first byte helps when reading a pcap.
    static constexpr std::array<std::uint8_t, 8> kSegPayload = {
        'P','4','D','a','t','a','0','1'};

    // Three retransmissions give three RTO values, the fewest that show whether the
    // steps between them grow (TcpRetransmissionTo04Captured).
    static constexpr std::uint8_t kRetransmissions = 3;
    static constexpr std::array<std::string_view, kRetransmissions> kRetransmissionWaits = {
        "dut_data_retransmission_1", "dut_data_retransmission_2", "dut_data_retransmission_3"};

    // The DUT sends the data segment as soon as the SEND reaches it.
    static constexpr std::chrono::milliseconds kFirstSegmentBound{5000};
    // A retransmission the wire showed is counted by the DUT a moment after it is sent
    // (Linux sends it, then doubles the RTO and counts it); its counter is polled at this
    // cadence, for at most this long, until it agrees.
    static constexpr std::chrono::milliseconds kPollInterval{20};
    static constexpr std::chrono::milliseconds kCounterSettleBound{1000};

    // The DUT's TCP_INFO once it counts at least `k` retransmissions; empty when it
    // does not within kCounterSettleBound, or cannot be read.
    static std::optional<::tc8::sce::DutTcpInfo> snapshotAfter(::tc8::sce::StimulusContext& ctx,
                                                               ::tc8::sce::DutSocket sock,
                                                               std::uint8_t k) {
        const auto until = std::chrono::steady_clock::now() + kCounterSettleBound;
        while (true) {
            const auto info = ctx.dut.tcpInfoProbe()->queryInfo(sock);
            if (info && info->retransmits >= k) {
                return info;
            }
            if (std::chrono::steady_clock::now() >= until) {
                return std::nullopt;
            }
            std::this_thread::sleep_for(kPollInterval);
        }
    }

    static void store(Captured& c, std::uint8_t k, const std::optional<::tc8::sce::DutTcpInfo>& s) {
        const ::tc8::sce::DutTcpInfo v = s.value_or(::tc8::sce::DutTcpInfo{});
        switch (k) {
            case 1:
                c.ut_tcpi_p1_valid = s.has_value();
                c.ut_tcpi_p1_state = v.state;
                c.ut_tcpi_p1_rto_us = v.rto_us;
                c.ut_tcpi_p1_retransmits = v.retransmits;
                c.ut_tcpi_p1_unacked = v.unacked;
                break;
            case 2:
                c.ut_tcpi_p2_valid = s.has_value();
                c.ut_tcpi_p2_state = v.state;
                c.ut_tcpi_p2_rto_us = v.rto_us;
                c.ut_tcpi_p2_retransmits = v.retransmits;
                c.ut_tcpi_p2_unacked = v.unacked;
                break;
            default:
                c.ut_tcpi_p3_valid = s.has_value();
                c.ut_tcpi_p3_state = v.state;
                c.ut_tcpi_p3_rto_us = v.rto_us;
                c.ut_tcpi_p3_retransmits = v.retransmits;
                c.ut_tcpi_p3_unacked = v.unacked;
                break;
        }
    }

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        using namespace ::tc8::sce::tcp;
        using std::chrono::microseconds;

        const std::uint16_t local_port  =
            kBasicsActiveLocalPort  + kTcpRetransmissionTo04LocalOffset;
        const std::uint16_t remote_port =
            kBasicsActiveRemotePort + kTcpRetransmissionTo04LocalOffset;

        // Spec step 1: active OPEN to ESTABLISHED through the backend-agnostic seam.
        auto open = driveSeamActiveOpen(ctx.dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0) return;

        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (!seq_range.has_value() || !open.conn) {
            ::close(tester_fd);
            return;
        }
        const ::tc8::sce::DutSocket dut_sock = open.conn->socket;

        // Prelude success: the SCXML's first cond gates on it, so a negative IP-flip row
        // lands on `inconclusive_handshake_did_not_complete`.
        c.ut_handshake_completed = true;

        // Spec step 4 for the whole body: the tester's kernel would acknowledge the data
        // segment, so its ACKs are dropped on egress until the stimulus returns.
        TesterAutoAckDrop ack_drop(cfg);

        // Spec steps 2-3: a data SEND, and the DUT's data segment.
        const std::uint32_t seg_seq = seq_range->rcv_nxt;
        const auto seg_len = static_cast<std::uint32_t>(kSegPayload.size());
        const ::tc8::sce::ObservationCursor before_send = ctx.observer.mark();
        seamSendTcp(ctx.dut, dut_sock, kSegPayload);
        const auto first = ctx.observer.awaitObservation(
            "dut_data_segment", before_send,
            dutDataSegmentAt(cfg.dut.ip, local_port, seg_seq, seg_len), kFirstSegmentBound);
        if (!first) return;
        c.segment_ts_us[0] = segmentOf(first->view()).observed_ts_us;

        // Spec steps 5-6: each retransmission, waited for as long as the DUT's own RTO
        // says it will take (tcp_retransmission_timing.h), then the RTO the DUT now
        // holds for the next one. The first wait uses the RTO read once the segment is out.
        const auto initial = ctx.dut.tcpInfoProbe()->queryInfo(dut_sock);
        microseconds rto{initial ? initial->rto_us : 0U};
        microseconds last_interval{0};
        for (std::uint8_t k = 1; k <= kRetransmissions; ++k) {
            const auto retransmission = ctx.observer.observeWithin(
                kRetransmissionWaits[k - 1], before_send,
                dutDataSegmentAt(cfg.dut.ip, local_port, seg_seq, seg_len, c.segment_ts_us[k - 1]),
                nextRetransmissionBound(rto, last_interval));
            if (!retransmission) {
                // The window elapsed with nothing on the wire. The DUT's counter tells a
                // retransmission the capture missed from one the DUT never sent.
                const auto now = ctx.dut.tcpInfoProbe()->queryInfo(dut_sock);
                c.missed_query_valid = now.has_value();
                c.missed_retransmits = now ? now->retransmits : std::uint8_t{0};
                break;
            }
            c.segment_ts_us[k] = segmentOf(retransmission->view()).observed_ts_us;
            c.retransmissions_seen = k;
            last_interval = microseconds(c.segment_ts_us[k] - c.segment_ts_us[k - 1]);
            const auto snapshot = snapshotAfter(ctx, dut_sock, k);
            store(c, k, snapshot);
            rto = microseconds(snapshot ? snapshot->rto_us : 0U);
        }
        (void)tester_fd;
    }

    static void dispatch(Captured& /*c*/, SM& /*sm*/, const ::tc8::CapturedEvent& /*ev*/) {
        // The stimulus has seen every frame the verdict needs (through the observer, on
        // the case's own capture) and left the times and RTO values in `captured`; the
        // machine evaluates them on the `evaluate` it raises at entry, so frame ingress
        // drives nothing.
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpRetransmissionTo04SM, tcp_retransmission_to_04)
