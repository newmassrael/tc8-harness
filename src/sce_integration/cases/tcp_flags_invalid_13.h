#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <unistd.h>

#include <sys/socket.h>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_flags_invalid_13_sm.h"

namespace tc8::sce::cases {

using TcpFlagsInvalid13SM = ::SCE::Generated::tcp_flags_invalid_13::tcp_flags_invalid_13;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpFlagsInvalid13SM>
    : TcpAnyBase<cases::TcpFlagsInvalid13SM> {
    static constexpr std::string_view kCaseId       = "TCP_FLAGS_INVALID_13";
    static constexpr std::string_view kSpecSection  = "4.8.6.6";
    static constexpr std::string_view kDescription  =
        "TCP in LAST-ACK state MUST send an ACK with next expected "
        "SEQ number after receiving any segment with OTW SEQ number "
        "(RFC 793 §3.9 p69 Event Processing). 5 spec iterations "
        "exercise flag set ∈ {SYN, SYN+ACK, ACK, FIN, data}";

    static constexpr std::array<std::uint8_t, 4> kCorruptPayload = {
        0xCAU, 0xFEU, 0xBAU, 0xBEU};

    // Function-scoped TesterAutoAckDrop installed at top: iptables
    // OUTPUT drops tester-kernel pure ACK toward DUT for the entire
    // stimulus, preventing the auto-ACK to DUT FIN from advancing
    // DUT past LAST-ACK on every phase. Per phase: handshake →
    // tester shutdown(SHUT_WR) (tester FIN, DUT auto-ACK observed,
    // DUT CW) → 100 ms settle → the seam CLOSE (DUT FIN+ACK, tester ACK
    // suppressed by ack_drop, DUT LA) → 100 ms settle →
    // queryTcpSeqRange → CASE-distinct OTW probe with ack_num =
    // rcv_nxt - 1 (acceptable but does NOT acknowledge DUT FIN).
    // Same convention as FLAGS_INVALID_08 / _09 / _10 / _11 for
    // CASE 4 carrying ACK with rcv_nxt - 1.
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        TesterAutoAckDrop ack_drop(cfg);
        (void)ack_drop;

        for (std::uint16_t phase = 0; phase < 5U; ++phase) {
            const std::uint16_t local_port  = kBasicsActiveLocalPort  + phase;
            const std::uint16_t remote_port = kBasicsActiveRemotePort + phase;
            auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
            const int tester_fd = open.listener.acceptOne();
            if (tester_fd < 0) {
                std::this_thread::sleep_for(kTcpPilotPhaseGap);
                continue;
            }
            ::shutdown(tester_fd, SHUT_WR);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            if (open.conn) dut.tcpControl()->closeTcp(open.conn->socket);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            const auto seq_range = queryTcpSeqRange(tester_fd);
            if (!seq_range.has_value()) {
                std::this_thread::sleep_for(kTcpPilotPhaseGap);
                continue;
            }

            // Spec literal "ACK with next expected SEQ number" — DUT
            // challenge ACK in LAST-ACK carries ack_num == DUT.rcv.nxt
            // == post-tester-FIN tester.snd_nxt == seq_range->snd_nxt.
            // Per-phase slot for kernel-chosen ISN_t.
            switch (phase) {
                case 0:  c.expected_ack_num        = seq_range->snd_nxt; break;
                case 1:  c.expected_ack_num_phase2 = seq_range->snd_nxt; break;
                case 2:  c.expected_ack_num_phase3 = seq_range->snd_nxt; break;
                case 3:  c.expected_ack_num_phase4 = seq_range->snd_nxt; break;
                default: c.expected_ack_num_phase5 = seq_range->snd_nxt; break;
            }
            ::tc8::stimulus::TcpSegmentSpec probe{};
            probe.src_port = remote_port;
            probe.dst_port = local_port;
            probe.seq_num  = seq_range->snd_nxt + kOutOfWindowSeqOffset;
            switch (phase) {
                case 0:  // CASE 1: SYN-only
                    probe.flags   = ::tc8::stimulus::kTcpFlagSyn;
                    probe.ack_num = 0U;
                    break;
                case 1:  // CASE 2: SYN+ACK
                    probe.flags   = ::tc8::stimulus::kTcpFlagSyn
                                  | ::tc8::stimulus::kTcpFlagAck;
                    probe.ack_num = seq_range->rcv_nxt - 1U;
                    break;
                case 2:  // CASE 3: ACK
                    probe.flags   = ::tc8::stimulus::kTcpFlagAck;
                    probe.ack_num = seq_range->rcv_nxt - 1U;
                    break;
                case 3:  // CASE 4: FIN+ACK
                    probe.flags   = ::tc8::stimulus::kTcpFlagFin
                                  | ::tc8::stimulus::kTcpFlagAck;
                    probe.ack_num = seq_range->rcv_nxt - 1U;
                    break;
                default:  // CASE 5: data segment
                    probe.flags   = ::tc8::stimulus::kTcpFlagPsh
                                  | ::tc8::stimulus::kTcpFlagAck;
                    probe.ack_num = seq_range->rcv_nxt - 1U;
                    probe.payload.assign(kCorruptPayload.begin(),
                                         kCorruptPayload.end());
                    break;
            }
            emitTcpFrame(cfg, iface, cfg.dut.mac, probe,
                         /*initial_wait=*/std::chrono::milliseconds(0));
            (void)tester_fd;
            std::this_thread::sleep_for(kTcpPilotPhaseGap);
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsInvalid13SM, tcp_flags_invalid_13)
