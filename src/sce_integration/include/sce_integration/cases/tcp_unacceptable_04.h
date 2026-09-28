#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>
#include <unistd.h>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_unacceptable_04_sm.h"

namespace tc8::sce::cases {

using TcpUnacceptable04SM = ::SCE::Generated::tcp_unacceptable_04::tcp_unacceptable_04;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpUnacceptable04SM>
    : TcpDutDrivenBase<cases::TcpUnacceptable04SM> {
    static constexpr std::string_view kCaseId       = "TCP_UNACCEPTABLE_04";
    static constexpr std::string_view kDescription  =
        "TCP in ESTABLISHED state MUST return ACK with proper SEQ and "
        "ACK numbers after receiving a segment with OTW SEQ or "
        "unacceptable ACK (RFC 793 §3.4 p37 Establishing a Connection)";

    static constexpr std::array<std::uint8_t, 4> kCorruptPayload = {
        0xDEU, 0xADU, 0xBEU, 0xEFU};

    // Case shape — two iterations,
    // both exercised:
    //   * Phase 1 — fired synchronously: data segment with OTW SEQ
    //     (snd_nxt + kOutOfWindowSeqOffset).
    //   * Phase 2 — deferred via scheduleAfterStateEntry on
    //     Listening_unacc_ack: data segment with in-window SEQ
    //     (tester snd_nxt) + unacceptable ACK (tester rcv_nxt +
    //     kUnacceptableAckOffset, after DUT's snd_nxt). In-window
    //     SEQ ensures tcp_validate_incoming does NOT short-circuit
    //     at the OTW path before tcp_ack examines the ACK. Same
    //     stimulus shape as UNACCEPTABLE_09 CASE 2.
    //
    // Phase 2 is the one a Linux DUT has answered differently across
    // kernels. Linux 6.5 silently discarded it in ESTABLISHED
    // (tcp_rcv_established slow path, step 5: tcp_ack returns
    // -SKB_DROP_REASON_TCP_ACK_UNSENT_DATA and the segment is
    // discarded with no challenge ACK), so the case could only time
    // out to inconclusive_no_dut_ack_to_unacc_ack. Kernel 7.0.0-31
    // answers it with a pure ACK (ack = the tester's rcv_nxt, measured
    // single-pc 2026-09-24), and the case passes; it carries no
    // known-fail mark. See the SCXML preamble for the per-state table.
    //
    // Active-OPEN handshake → ESTABLISHED → query tester's
    // snd_nxt / rcv_nxt → raw-inject phase 1 → on Listening_unacc_ack
    // entry, re-query seq range and raw-inject phase 2 → expect a
    // second DUT pure ACK on the same active port quad. The tester_fd
    // remains open across phases (caller-owned per acceptOne contract;
    // kept alive until process exit, same rationale as CHECKSUM_02).
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        using namespace ::tc8::sce::tcp;

        auto open = driveSeamActiveOpen(
            ctx.dut, cfg,
            kBasicsActiveLocalPort  + kTcpUnacceptable04LocalOffset,
            kBasicsActiveRemotePort + kTcpUnacceptable04LocalOffset);

        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0) return;

        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (!seq_range.has_value()) return;

        ::tc8::stimulus::TcpSegmentSpec phase1{};
        phase1.src_port = kBasicsActiveRemotePort + kTcpUnacceptable04LocalOffset;
        phase1.dst_port = kBasicsActiveLocalPort  + kTcpUnacceptable04LocalOffset;
        phase1.seq_num  = seq_range->snd_nxt + kOutOfWindowSeqOffset;
        phase1.ack_num  = seq_range->rcv_nxt;
        phase1.flags    = ::tc8::stimulus::kTcpFlagPsh
                        | ::tc8::stimulus::kTcpFlagAck;
        phase1.payload.assign(kCorruptPayload.begin(),
                              kCorruptPayload.end());
        emitTcpFrame(cfg, ctx.iface, cfg.dut.mac, phase1,
                     /*initial_wait=*/std::chrono::milliseconds(0));

        ::tc8::TestConfig cfg_copy = cfg;
        std::string       iface_str(ctx.iface);
        ctx.scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_unacc_ack),
            [cfg_copy, iface_str, tester_fd]() {
                using namespace ::tc8::sce::tcp;
                const auto seq_range_p2 = queryTcpSeqRange(tester_fd);
                if (!seq_range_p2.has_value()) return;
                ::tc8::stimulus::TcpSegmentSpec phase2{};
                phase2.src_port = kBasicsActiveRemotePort + kTcpUnacceptable04LocalOffset;
                phase2.dst_port = kBasicsActiveLocalPort  + kTcpUnacceptable04LocalOffset;
                phase2.seq_num  = seq_range_p2->snd_nxt;
                phase2.ack_num  = seq_range_p2->rcv_nxt + kUnacceptableAckOffset;
                phase2.flags    = ::tc8::stimulus::kTcpFlagPsh
                                | ::tc8::stimulus::kTcpFlagAck;
                phase2.payload.assign(kCorruptPayload.begin(),
                                      kCorruptPayload.end());
                emitTcpFrame(cfg_copy, iface_str, cfg_copy.dut.mac, phase2,
                             /*initial_wait=*/std::chrono::milliseconds(0));
            });

        (void)tester_fd;
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpUnacceptable04SM, tcp_unacceptable_04)
