#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_flags_processing_11_sm.h"

namespace tc8::sce::cases {

using TcpFlagsProcessing11SM =
    ::SCE::Generated::tcp_flags_processing_11::tcp_flags_processing_11;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpFlagsProcessing11SM>
    : TcpAnyBase<cases::TcpFlagsProcessing11SM> {
    static constexpr std::string_view kCaseId       = "TCP_FLAGS_PROCESSING_11";
    static constexpr std::string_view kSpecSection  = "4.8.6.7";
    static constexpr std::string_view kDescription  =
        "TCP in ESTABLISHED state MUST ignore a duplicate ACK "
        "(RFC 793 §3.9 p72 Event Processing)";

    // The ESTABLISHED verdict reads DUT kernel TCP_INFO state (opcode-only);
    // kCapTcpStateProbe makes the CLI capability gate honestly SKIP this case
    // on a testability backend (Tier 2 2b#4) instead of failing it. The active
    // OPEN itself completes a normal handshake against a tester listener, which
    // both backends support.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl | ::tc8::sce::kCapTcpStateProbe;

    // Active-OPEN handshake on (kBasicsActiveLocalPort + 50,
    // kBasicsActiveRemotePort + 50) → DUT in ESTABLISHED. Snapshot
    // tester snd_nxt / rcv_nxt via queryTcpSeqRange (= the
    // post-handshake ACK shape: seq = ISN_t + 1, ack = ISN_d + 1).
    // Synchronously fetch DUT's TCP_INFO via the seam state probe
    // and write into `captured.ut_established` BEFORE the SCXML arms,
    // so the handshake_ack pass guard's `ut_established == 1` conjunct
    // resolves against a known value. Then raw-inject the duplicate
    // ACK and leave the tester socket open through process exit (same
    // pattern as FLAGS_INVALID_08): the active-OPEN socket is not
    // re-used and Linux teardown is well within the smoke watchdog
    // budget.
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        constexpr std::uint16_t kPortOffset = 50U;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kPortOffset;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kPortOffset;

        // Active OPEN routed through the backend-agnostic seam; the helper's
        // tester listener (held in `open`) is accepted here for the tester-side
        // seq snapshot below.
        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0) return;

        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (!seq_range.has_value()) return;

        // DUT TCP_INFO state read via the seam state probe (opcode-only;
        // testability is capability-skipped). utEstablishedByte owns the
        // tristate-to-byte encoding.
        c.ut_established = open.conn
            ? utEstablishedByte(dut.tcpStateProbe()->isEstablished(open.conn->socket))
            : 0xFFU;

        ::tc8::stimulus::TcpSegmentSpec dup_ack{};
        dup_ack.src_port = remote_port;
        dup_ack.dst_port = local_port;
        dup_ack.seq_num  = seq_range->snd_nxt;
        dup_ack.ack_num  = seq_range->rcv_nxt;
        dup_ack.flags    = ::tc8::stimulus::kTcpFlagAck;
        emitTcpFrame(cfg, iface, cfg.dut.mac, dup_ack,
                     /*initial_wait=*/std::chrono::milliseconds(0));
        (void)tester_fd;
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                       return "pass";
            case State::Fail_no_handshake_ack:      return "fail:no_dut_handshake_ack";
            case State::Fail_unexpected_response:   return "fail:dut_emitted_response_to_duplicate_ack_in_est";
            default:                                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsProcessing11SM, tcp_flags_processing_11)
