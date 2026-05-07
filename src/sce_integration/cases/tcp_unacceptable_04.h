#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>
#include <unistd.h>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_unacceptable_04_sm.h"

namespace tc8::sce::cases {

using TcpUnacceptable04SM = ::SCE::Generated::tcp_unacceptable_04::tcp_unacceptable_04;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpUnacceptable04SM>
    : TcpAnyBase<cases::TcpUnacceptable04SM> {
    static constexpr std::string_view kCaseId       = "TCP_UNACCEPTABLE_04";
    static constexpr std::string_view kSpecSection  = "4.8.6.3";
    static constexpr std::string_view kDescription  =
        "TCP in ESTABLISHED state MUST return ACK with proper SEQ and "
        "ACK numbers after receiving a segment with OTW SEQ or "
        "unacceptable ACK (RFC 793 §3.4 p37 Establishing a Connection)";

    static constexpr std::array<std::uint8_t, 4> kCorruptPayload = {
        0xDEU, 0xADU, 0xBEU, 0xEFU};

    // Spec Test Procedure (v3.0 p301-p320.txt:357), two iterations,
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
    // Linux 6.5 ESTABLISHED silent-drops phase 2's unacc-ACK
    // (tcp_rcv_established slow_path step5 → tcp_ack returns -1
    // -SKB_DROP_REASON_TCP_ACK_UNSENT_DATA → goto discard, no
    // challenge ACK). Linux DUT therefore lands
    // `fail_no_dut_ack_to_unacc_ack`; case is excluded from CI green
    // via grep filter in .github/workflows/smoke-test.yml. A
    // strict-RFC DUT lands pass without filter. See SCXML preamble +
    // reference_unacc_ack_dispatch memory for the source trace.
    //
    // Active-OPEN handshake → ESTABLISHED → query tester's
    // snd_nxt / rcv_nxt → raw-inject phase 1 → on Listening_unacc_ack
    // entry, re-query seq range and raw-inject phase 2 → expect a
    // second DUT pure ACK on the same active port quad. The tester_fd
    // remains open across phases (caller-owned per acceptOne contract;
    // kept alive until process exit, same rationale as CHECKSUM_02).
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        auto listener = driveActiveOpenEstablished(
            cfg, iface, cfg.arp.dut_real_mac);

        const int tester_fd = listener.acceptOne();
        if (tester_fd < 0) return;

        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (!seq_range.has_value()) return;

        ::tc8::stimulus::TcpSegmentSpec phase1{};
        phase1.src_port = kBasicsActiveRemotePort;
        phase1.dst_port = kBasicsActiveLocalPort;
        phase1.seq_num  = seq_range->snd_nxt + kOutOfWindowSeqOffset;
        phase1.ack_num  = seq_range->rcv_nxt;
        phase1.flags    = ::tc8::stimulus::kTcpFlagPsh
                        | ::tc8::stimulus::kTcpFlagAck;
        phase1.payload.assign(kCorruptPayload.begin(),
                              kCorruptPayload.end());
        emitTcpFrame(cfg, iface, cfg.arp.dut_real_mac, phase1,
                     /*initial_wait=*/std::chrono::milliseconds(0));

        ::tc8::TestConfig cfg_copy = cfg;
        std::string       iface_str(iface);
        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_unacc_ack),
            [cfg_copy, iface_str, tester_fd]() {
                using namespace ::tc8::sce::tcp;
                const auto seq_range_p2 = queryTcpSeqRange(tester_fd);
                if (!seq_range_p2.has_value()) return;
                ::tc8::stimulus::TcpSegmentSpec phase2{};
                phase2.src_port = kBasicsActiveRemotePort;
                phase2.dst_port = kBasicsActiveLocalPort;
                phase2.seq_num  = seq_range_p2->snd_nxt;
                phase2.ack_num  = seq_range_p2->rcv_nxt + kUnacceptableAckOffset;
                phase2.flags    = ::tc8::stimulus::kTcpFlagPsh
                                | ::tc8::stimulus::kTcpFlagAck;
                phase2.payload.assign(kCorruptPayload.begin(),
                                      kCorruptPayload.end());
                emitTcpFrame(cfg_copy, iface_str, cfg_copy.arp.dut_real_mac, phase2,
                             /*initial_wait=*/std::chrono::milliseconds(0));
            });

        (void)tester_fd;
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                          return "pass";
            case State::Fail_no_handshake_ack:         return "fail:no_dut_handshake_ack_within_listen_window";
            case State::Fail_no_otw_seq_ack:           return "fail:no_dut_ack_to_otw_seq_data";
            case State::Fail_no_dut_ack_to_unacc_ack:  return "fail:no_dut_ack_to_unacc_ack_data";
            default:                                   return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpUnacceptable04SM, tcp_unacceptable_04)
