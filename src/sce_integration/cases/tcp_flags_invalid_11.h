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

#include "tcp_flags_invalid_11_sm.h"

namespace tc8::sce::cases {

using TcpFlagsInvalid11SM = ::SCE::Generated::tcp_flags_invalid_11::tcp_flags_invalid_11;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpFlagsInvalid11SM>
    : TcpAnyBase<cases::TcpFlagsInvalid11SM> {
    static constexpr std::string_view kCaseId       = "TCP_FLAGS_INVALID_11";
    static constexpr std::string_view kSpecSection  = "4.8.6.6";
    static constexpr std::string_view kDescription  =
        "TCP in CLOSE-WAIT state MUST send an ACK with next expected "
        "SEQ number after receiving any segment with OTW SEQ number "
        "(RFC 793 §3.9 p69 Event Processing). 5 spec iterations "
        "exercise flag set ∈ {SYN, SYN+ACK, ACK, FIN, data}";

    static constexpr std::array<std::uint8_t, 4> kCorruptPayload = {
        0xDEU, 0xADU, 0xBEU, 0xEFU};

    // Per phase: independent active-OPEN handshake on its own port
    // quad → tester shutdown(SHUT_WR) drives DUT into CLOSE-WAIT
    // (DUT auto-ACKs FIN) → 100 ms post-FIN settle so Linux's
    // TCP_REPAIR view of SND.NXT reflects the consumed FIN
    // (rationale: same race as UNACCEPTABLE_14) → queryTcpSeqRange →
    // raw-inject probe with seq = snd_nxt + kOutOfWindowSeqOffset
    // and CASE-specific flag set → DUT empty ACK on the same port
    // quad. CASE 4 (FIN) carries an ACK flag with rcv_nxt because
    // Linux drops bare-FIN segments before reaching tcp_validate
    // _incoming's OTW SEQ branch — same convention as
    // FLAGS_INVALID_08.
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

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
            const auto seq_range = queryTcpSeqRange(tester_fd);
            if (!seq_range.has_value()) {
                std::this_thread::sleep_for(kTcpPilotPhaseGap);
                continue;
            }

            // Spec literal "ACK with next expected SEQ number" — DUT
            // challenge ACK to OTW SEQ probe carries ack_num ==
            // DUT.rcv.nxt == tester.snd_nxt (post-tester-FIN). Per-
            // phase slot because each phase opens a fresh active-
            // OPEN with kernel-chosen ISN_t.
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
                case 3:  // CASE 4: FIN+ACK
                    probe.flags   = ::tc8::stimulus::kTcpFlagFin
                                  | ::tc8::stimulus::kTcpFlagAck;
                    probe.ack_num = seq_range->rcv_nxt;
                    break;
                default:  // CASE 5: data segment
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

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsInvalid11SM, tcp_flags_invalid_11)
