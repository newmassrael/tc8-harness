#pragma once

#include <array>
#include <chrono>
#include <cstdint>
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

    // Spec Test Procedure (v3.0 p301-p320.txt:357), two iterations.
    // Linux deviation: only CASE 1 (OTW SEQ) is exercised here —
    // ESTABLISHED is the only state on Linux 6.5 that silent-drops
    // CASE 2 (tcp_rcv_established slow_path step5 → tcp_ack
    // -SKB_DROP_REASON_TCP_ACK_UNSENT_DATA → goto discard, no
    // challenge ACK). FW2 RSTs via tcp_timewait_state_process; all
    // other non-EST states challenge-ACK via tcp_rcv_state_process.
    // See SCXML preamble + reference_unacc_ack_dispatch memory.
    // CASE 2 against Linux is covered by UNACCEPTABLE_09 (FW1),
    // _11 (CLOSING), _12 (LA), _14 (CW).
    //
    // Active-OPEN handshake → ESTABLISHED → query tester's
    // snd_nxt / rcv_nxt → raw-inject DATA with seq = snd_nxt + 16 MB
    // (safely OTW for any plausible window scale) → DUT empty ACK on
    // the active port quad. Connection cleanup deferred to process
    // exit (same rationale as CHECKSUM_02).
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        auto listener = driveActiveOpenEstablished(
            cfg, iface, cfg.arp.dut_real_mac);

        const int tester_fd = listener.acceptOne();
        if (tester_fd >= 0) {
            const auto seq_range = queryTcpSeqRange(tester_fd);
            if (seq_range.has_value()) {
                ::tc8::stimulus::TcpSegmentSpec data{};
                data.src_port = kBasicsActiveRemotePort;
                data.dst_port = kBasicsActiveLocalPort;
                data.seq_num  = seq_range->snd_nxt + kOutOfWindowSeqOffset;
                data.ack_num  = seq_range->rcv_nxt;
                data.flags    = ::tc8::stimulus::kTcpFlagPsh
                              | ::tc8::stimulus::kTcpFlagAck;
                data.payload.assign(kCorruptPayload.begin(),
                                    kCorruptPayload.end());
                emitTcpFrame(cfg, iface, cfg.arp.dut_real_mac, data,
                             /*initial_wait=*/std::chrono::milliseconds(0));
            }
            (void)tester_fd;
        }
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                          return "pass";
            case State::Fail_no_handshake_ack:         return "fail:no_dut_handshake_ack_within_listen_window";
            case State::Fail_no_otw_seq_ack:           return "fail:no_dut_ack_to_otw_seq_data";
            default:                                   return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpUnacceptable04SM, tcp_unacceptable_04)
