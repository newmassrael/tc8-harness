#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string_view>
#include <thread>
#include <unistd.h>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"

#include "tcp_retransmission_to_04_sm.h"

namespace tc8::sce::cases {

using TcpRetransmissionTo04SM =
    ::SCE::Generated::tcp_retransmission_to_04::tcp_retransmission_to_04;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpRetransmissionTo04SM>
    : TcpAnyBase<cases::TcpRetransmissionTo04SM> {
    static constexpr std::string_view kCaseId       = "TCP_RETRANSMISSION_TO_04";
    static constexpr std::string_view kSpecSection  = "4.8.6.11";
    static constexpr std::string_view kDescription  =
        "DUT TCP MUST include exponential backoff (more than linear) "
        "for successive RTO values for data segments (RFC 1122 "
        "§4.2.3.1 — RFC 6298 §5).";

    // Distinct first byte aids pcap visual inspection; payload is well
    // under upper_tester_protocol.h kMaxPayload (256 B) and far below
    // MSS so Nagle is irrelevant — a single data segment is enough to
    // exercise `tcp_retransmit_timer`'s exponential-backoff branch.
    static constexpr std::array<std::uint8_t, 8> kSegPayload = {
        'P','4','D','a','t','a','0','1'};

    // Hold-window for the deferred TesterAutoAckDrop release. Linux's
    // data-RTO sequence on a fresh local-veth ESTABLISHED socket
    // (RTO_MIN=200 ms baseline doubling each retx) lands retx 1/2/3
    // at ~200 / 600 / 1400 ms post-seg1; SCXML phase budget
    // (5 + 1 + 1.5 + 2 = 9.5 s) plus the ~3 s prelude (UT boot +
    // handshake + ACK-drop install) sets a comfortable 13 s envelope.
    static constexpr std::chrono::milliseconds kAckDropHold{13000};

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  =
            kBasicsActiveLocalPort  + kTcpRetransmissionTo04LocalOffset;
        const std::uint16_t remote_port =
            kBasicsActiveRemotePort + kTcpRetransmissionTo04LocalOffset;

        // ESTABLISHED prelude: tester listener answers the DUT's
        // active-OPEN SYN with SYN+ACK (kernel handshake), then
        // `acceptOne()` returns a userland fd on the tester side that
        // queryTcpSeqRange uses for clean pcap-time tester snapshot.
        // accepted_fd is unused after queryTcpSeqRange — the harness
        // does not need to send anything from userland; the iptables
        // OUTPUT rule below silently swallows the kernel's auto-ACK
        // to the DUT's data segment.
        auto listener = driveActiveOpenEstablished(
            cfg, iface, cfg.arp.dut_real_mac,
            /*open_req_id=*/1, local_port, remote_port);
        const int tester_fd = listener.acceptOne();
        if (tester_fd < 0) return;

        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (!seq_range.has_value()) {
            ::close(tester_fd);
            return;
        }

        // shared_ptr-and-scheduler.schedule lifetime extension: the
        // ack_drop scope must outlive the entire 4-state observation
        // budget (~9.5 s); a body-scoped TesterAutoAckDrop would die
        // at stimulus return — i.e. before the SCXML listen window
        // even opens — and the tester kernel's auto-ACK to seg1 would
        // race ahead of the harness's iptables rule, advancing
        // snd_una and disarming the retransmit timer.
        auto ack_drop = std::make_shared<TesterAutoAckDrop>(cfg);

        // Spec step 2-3: SEND → DUT data segment. With ack_drop active
        // the tester kernel's auto-ACK is silently dropped on egress;
        // the DUT's snd_una stays at seg_seq, the retransmit timer
        // fires when icsk_rto elapses, and `tcp_retransmit_timer`
        // doubles icsk_rto on every fire (state == TCP_ESTABLISHED
        // takes the "Use normal (exponential) backoff" branch
        // unconditionally — Linux's tcp_syn_linear_timeouts knob
        // applies only to TCP_SYN_SENT).
        sendSendTcpDataRequest(
            cfg, iface, cfg.arp.dut_real_mac,
            /*req_id=*/2, /*socket_id=*/1,
            kSegPayload.data(),
            static_cast<std::uint16_t>(kSegPayload.size()));

        scheduler.schedule(kAckDropHold, [ack_drop]() {
            (void)ack_drop;
        });

        (void)tester_fd;
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                              return "pass";
            case State::Fail_no_seg1:                      return "fail:no_dut_first_data_segment";
            case State::Fail_no_retx_1:                    return "fail:no_dut_data_retransmit_1";
            case State::Fail_no_retx_2:                    return "fail:no_dut_data_retransmit_2";
            case State::Fail_no_retx_3:                    return "fail:no_dut_data_retransmit_3";
            case State::Fail_initial_rto_out_of_window:    return "fail:data_retx1_rto_out_of_baseline_window";
            case State::Fail_retx2_not_doubled:            return "fail:data_retx2_delta_not_greater_than_initial_rto";
            case State::Fail_retx3_not_doubled:            return "fail:data_retx3_delta_not_greater_than_retx2_lower_bound";
            default:                                       return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpRetransmissionTo04SM, tcp_retransmission_to_04)
