#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <unistd.h>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_flags_invalid_08_sm.h"

namespace tc8::sce::cases {

using TcpFlagsInvalid08SM = ::SCE::Generated::tcp_flags_invalid_08::tcp_flags_invalid_08;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpFlagsInvalid08SM>
    : TcpAnyBase<cases::TcpFlagsInvalid08SM> {
    static constexpr std::string_view kCaseId       = "TCP_FLAGS_INVALID_08";
    static constexpr std::string_view kDescription  =
        "TCP in ESTABLISHED state MUST send an ACK with next expected "
        "SEQ number after receiving any segment with OTW SEQ number "
        "(RFC 793 §3.9 p69 Event Processing). 5 spec iterations exercise "
        "flag set ∈ {SYN, SYN+ACK, ACK, FIN, data}";

    static constexpr std::array<std::uint8_t, 4> kCorruptPayload = {
        0xDEU, 0xADU, 0xBEU, 0xEFU};

    // Per phase: independent active-OPEN handshake on its own port
    // quad → queryTcpSeqRange snapshot → raw-inject probe with seq =
    // snd_nxt + kOutOfWindowSeqOffset and CASE-specific flag set →
    // DUT empty ACK on the same port quad. tester_fd is intentionally
    // leaked across phases (process exit cleanup, same rationale as
    // CHECKSUM_02 / UNACCEPTABLE_04) — the active-OPEN socket is not
    // re-used and Linux teardown of N=5 sockets is well within the
    // smoke watchdog budget.
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        for (std::uint16_t phase = 0; phase < 5U; ++phase) {
            const std::uint16_t local_port  = kBasicsActiveLocalPort  + kTcpFlagsInvalid08BaseOffset + phase;
            const std::uint16_t remote_port = kBasicsActiveRemotePort + kTcpFlagsInvalid08BaseOffset + phase;
            auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
            const int tester_fd = open.listener.acceptOne();
            if (tester_fd < 0) {
                std::this_thread::sleep_for(kTcpPilotPhaseGap);
                continue;
            }
            const auto seq_range = queryTcpSeqRange(tester_fd);
            if (!seq_range.has_value()) {
                std::this_thread::sleep_for(kTcpPilotPhaseGap);
                continue;
            }

            // Spec literal "ACK with next expected SEQ number" — the
            // OTW SEQ probe (any flag set) elicits a DUT challenge
            // ACK with ack_num == DUT.rcv.nxt == tester.snd_nxt at
            // injection. Empirically confirmed via pcap 2026-05-07
            // for all 5 CASE shapes (SYN / SYN+ACK / ACK / FIN /
            // data). One slot per phase because each phase opens a
            // fresh active-OPEN with kernel-chosen ISN_t.
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
                    probe.ack_num = seq_range->rcv_nxt;
                    break;
                case 2:  // CASE 3: ACK
                    probe.flags   = ::tc8::stimulus::kTcpFlagAck;
                    probe.ack_num = seq_range->rcv_nxt;
                    break;
                case 3:  // CASE 4: FIN (with ACK; bare-FIN without
                         // ACK is dropped by Linux's tcp_v4_rcv
                         // before reaching tcp_validate_incoming's
                         // OTW SEQ branch, so the spec-targeted
                         // challenge ACK is unobservable for that
                         // shape; carrying ACK with rcv_nxt keeps
                         // the segment valid past the early-drop
                         // and reaches the OTW path)
                    probe.flags   = ::tc8::stimulus::kTcpFlagFin
                                  | ::tc8::stimulus::kTcpFlagAck;
                    probe.ack_num = seq_range->rcv_nxt;
                    break;
                default:  // CASE 5: data segment (PSH+ACK + payload)
                    probe.flags   = ::tc8::stimulus::kTcpFlagPsh
                                  | ::tc8::stimulus::kTcpFlagAck;
                    probe.ack_num = seq_range->rcv_nxt;
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

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsInvalid08SM, tcp_flags_invalid_08)
