#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam_active_open.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_basics_17_sm.h"

namespace tc8::sce::cases {

using TcpBasics17SM = ::SCE::Generated::tcp_basics_17::tcp_basics_17;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpBasics17SM>
    : TcpAnyBase<cases::TcpBasics17SM> {
    static constexpr std::string_view kCaseId       = "TCP_BASICS_17";
    static constexpr std::string_view kSpecSection  = "4.8.6.1";
    static constexpr std::string_view kDescription  =
        "TCP MUST support simultaneous OPEN attempts (RFC 1122 "
        "§4.2.2.10 p87, RFC 793 §3.4 simultaneous-open path).";

    // Two opcode-only dependencies force a testability SKIP (Tier 2 2b#4): the
    // DUT is held in SYN-SENT with no tester listener until the simultaneous-
    // open SYN+ACK establishes it (kCapTcpSynSentOpen — the testability CONNECT
    // SP cannot hold a socket in SYN-SENT), and the ESTABLISHED verdict reads
    // kernel TCP_INFO state (kCapTcpStateProbe). The opcode backend exposes
    // both, so it runs; testability lacks them and is honestly skipped.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl | ::tc8::sce::kCapTcpStateProbe |
        ::tc8::sce::kCapTcpSynSentOpen;

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  = static_cast<std::uint16_t>(
            kBasicsActiveLocalPort  + kTcpBasics17LocalOffset);
        const std::uint16_t remote_port = static_cast<std::uint16_t>(
            kBasicsActiveRemotePort + kTcpBasics17LocalOffset);

        TesterAutoRstDrop rst_drop(cfg);
        (void)rst_drop;

        // Snippet captures DUT's active-OPEN SYN to learn ISN_d before
        // the simultaneous-SYN inject — needed because the third-leg
        // ACK's seq/ack must reference the DUT's actual ISN, not a
        // guess.
        auto snippet = TcpFrameSnippet::forDutSyn(cfg, iface, local_port);

        // Seam active OPEN, no tester listener: the DUT starts in SYN-SENT and
        // reaches ESTABLISHED only via the simultaneous-open SYN+ACK injected
        // below (a tester listener would complete a normal handshake instead).
        auto open = driveSeamSynSentOpen(dut, cfg, local_port, remote_port);

        const auto dut_syn = snippet.tryCapture(
            std::chrono::milliseconds(1000));
        if (dut_syn.has_value()) {
            // Inject tester SYN to trigger simultaneous-OPEN. DUT in
            // SYN-SENT receives SYN-only on the same 4-tuple →
            // tcp_rcv_synsent_state_process branches to RFC 793 §3.4:
            // sets DUT to SYN-RCVD, queues SYN+ACK egress.
            ::tc8::stimulus::TcpSegmentSpec syn{};
            syn.src_port = remote_port;
            syn.dst_port = local_port;
            syn.seq_num  = kTesterInitialSeq;
            syn.flags    = ::tc8::stimulus::kTcpFlagSyn;
            emitTcpFrame(cfg, iface, cfg.dut.mac, syn,
                         /*initial_wait=*/std::chrono::milliseconds(0));

            // 200 ms covers the kernel's SYN-RCVD entry and SYN+ACK
            // egress (single-digit ms on same-host netns; headroom
            // for parallel-worker scheduler jitter).
            std::this_thread::sleep_for(std::chrono::milliseconds(200));

            // Inject third-leg ACK. seq advances by 1 (SYN consumes
            // a sequence number); ack acknowledges through DUT's SYN.
            ::tc8::stimulus::TcpSegmentSpec ack{};
            ack.src_port = remote_port;
            ack.dst_port = local_port;
            ack.seq_num  = kTesterInitialSeq + 1U;
            ack.ack_num  = dut_syn->seq_num + 1U;
            ack.flags    = ::tc8::stimulus::kTcpFlagAck;
            emitTcpFrame(cfg, iface, cfg.dut.mac, ack,
                         /*initial_wait=*/std::chrono::milliseconds(0));

            // 200 ms covers SYN-RCVD → ESTABLISHED transition + the
            // tc8-dut connect() worker's unblock + accepted_fd
            // assignment.
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }

        // Read kernel TCP_INFO state into Captured before SCXML's first
        // dispatch (same synchronous pattern as BASICS_07). tcpStateProbe() is
        // non-null by contract: the capability gate skips this case if the
        // backend lacks kCapTcpStateProbe. utEstablishedByte owns the
        // tristate-to-byte encoding.
        c.ut_established = open
            ? utEstablishedByte(dut.tcpStateProbe()->isEstablished(open->socket))
            : 0xFFU;

        if (open) dut.tcpControl()->closeTcp(open->socket);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                   return "pass";
            case State::Fail_not_established:   return "fail:dut_did_not_reach_established_after_simultaneous_open";
            case State::Fail_timeout:           return "fail:no_dut_synack_to_simultaneous_syn";
            default:                            return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpBasics17SM, tcp_basics_17)
