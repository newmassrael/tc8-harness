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

#include "tcp_unacceptable_10_sm.h"

namespace tc8::sce::cases {

using TcpUnacceptable10SM = ::SCE::Generated::tcp_unacceptable_10::tcp_unacceptable_10;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpUnacceptable10SM>
    : TcpAnyBase<cases::TcpUnacceptable10SM> {
    static constexpr std::string_view kCaseId       = "TCP_UNACCEPTABLE_10";
    static constexpr std::string_view kSpecSection  = "4.8.6.3";
    static constexpr std::string_view kDescription  =
        "TCP in FIN-WAIT-2 state MUST return ACK with proper SEQ and "
        "ACK numbers after receiving a segment with OTW SEQ or "
        "unacceptable ACK (RFC 793 §3.4 p37 Establishing a Connection)";

    static constexpr std::array<std::uint8_t, 4> kCorruptPayload = {
        0xCAU, 0xFEU, 0xBAU, 0xBEU};

    // Single-iter (CASE 1 OTW SEQ only). CASE 2 in FW2 emits RST
    // per Linux 6.5 tcp_minisocks.c::tcp_timewait_state_process
    // FW2 substate (line 130-135) — RFC 793 §3.4 spec violation,
    // NOT silent-drop. See SCXML preamble +
    // reference_unacc_ack_dispatch for the dispatch table.
    // Mechanism:
    //   1. Active-OPEN handshake → ESTABLISHED.
    //   2. UT OpCloseTcpSocket — DUT FIN → DUT enters FIN-WAIT-1.
    //   3. Tester kernel auto-ACKs DUT FIN (NOT suppressed) → DUT
    //      transitions FIN-WAIT-1 → FIN-WAIT-2. The 200 ms settle
    //      wait covers the auto-ACK round-trip + tester socket TCP
    //      state stabilisation before TCP_REPAIR query.
    //   4. queryTcpSeqRange(tester_fd) — tester snd_nxt = ISN_t + 1
    //      (no tester data); rcv_nxt = ISN_d + 2 (DUT FIN
    //      consumed +1).
    //   5. Build OTW-SEQ corrupt segment: seq_num = snd_nxt +
    //      kOutOfWindowSeqOffset, ack_num = rcv_nxt; payload set
    //      from kCorruptPayload because OTW-SEQ short-circuits in
    //      tcp_validate_incoming BEFORE the FIN-WAIT-2 abort-on-
    //      data RST path (which would fire only on payload + bad
    //      SEQ in some kernel configurations). CASE 2 (bad-ACK)
    //      is gated separately by tcp_ack's silent-drop and is
    //      not observable here — see SCXML preamble.
    //   6. Pcap observes DUT empty ACK on the data path.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        auto listener = driveActiveOpenEstablished(
            cfg, iface, cfg.arp.dut_real_mac);
        const int tester_fd = listener.acceptOne();
        sendCloseTcpSocketRequest(
            cfg, iface, cfg.arp.dut_real_mac,
            /*req_id=*/2, /*socket_id=*/1);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
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
        std::this_thread::sleep_for(kTcpPilotPhaseGap);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                       return "pass";
            case State::Fail_no_handshake_ack:      return "fail:no_dut_handshake_ack_within_listen_window";
            case State::Fail_no_dut_fin:            return "fail:no_dut_fin_within_listen_window";
            case State::Fail_no_data_ack:           return "fail:no_dut_ack_to_otw_seq_finwait2";
            default:                                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpUnacceptable10SM, tcp_unacceptable_10)
