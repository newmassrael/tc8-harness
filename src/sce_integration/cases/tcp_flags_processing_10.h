#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string_view>
#include <thread>
#include <vector>
#include <unistd.h>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam_active_open.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_flags_processing_10_sm.h"

namespace tc8::sce::cases {

using TcpFlagsProcessing10SM =
    ::SCE::Generated::tcp_flags_processing_10::tcp_flags_processing_10;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpFlagsProcessing10SM>
    : TcpAnyBase<cases::TcpFlagsProcessing10SM> {
    static constexpr std::string_view kCaseId       = "TCP_FLAGS_PROCESSING_10";
    static constexpr std::string_view kSpecSection  = "4.8.6.7";
    static constexpr std::string_view kDescription  =
        "DUT in ESTABLISHED MUST piggyback the acknowledgement onto a "
        "queued data segment when the tester injects ACK+payload that "
        "both opens the window and provides data to ack — within 0.5 "
        "sec (RFC 793 §3.9 SHOULD).";

    static constexpr std::array<std::uint8_t, 4> kFirstPayload = {
        'P', 'B', '1', 'A'};
    static constexpr std::array<std::uint8_t, 4> kSecondPayload = {
        'P', 'B', '2', 'A'};
    static constexpr std::array<std::uint8_t, 4> kTesterPayload = {
        0xC0U, 0xDEU, 0xCAU, 0xFEU};

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut,
                         IStimulusScheduler& scheduler) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  =
            kBasicsActiveLocalPort  + kTcpFlagsProcessing10LocalOffset;
        const std::uint16_t remote_port =
            kBasicsActiveRemotePort + kTcpFlagsProcessing10LocalOffset;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0 || !open.conn) return;

        const auto seq_range_pre = queryTcpSeqRange(tester_fd);
        if (!seq_range_pre.has_value()) {
            ::close(tester_fd);
            return;
        }
        const std::uint32_t first_seg_seq = seq_range_pre->rcv_nxt;
        const std::uint32_t tester_snd    = seq_range_pre->snd_nxt;
        c.expected_ack_num        = first_seg_seq;
        c.expected_ack_num_phase2 =
            tester_snd + static_cast<std::uint32_t>(kTesterPayload.size());

        auto ack_drop = std::make_shared<TesterAutoAckDrop>(cfg);

        dut.tcpControl()->sendTcp(
            open.conn->socket,
            std::vector<std::uint8_t>(kFirstPayload.begin(), kFirstPayload.end()),
            static_cast<std::uint16_t>(kFirstPayload.size()));
        // Gap must clear seg1's RTO (Linux TCP_RTO_MIN ~200 ms) so the
        // second SEND is enqueued after seg1's first retransmit instead
        // of racing it — a small SEND landing exactly at the RTO boundary
        // escapes Nagle and ships seg2 before the piggyback inject. The
        // opcode open's kTcpUtRpcWait slack masked this; the synchronous
        // seam open removes it, so widen the gap to keep the hold
        // deterministic on both backends.
        std::this_thread::sleep_for(std::chrono::milliseconds(350));

        dut.tcpControl()->sendTcp(
            open.conn->socket,
            std::vector<std::uint8_t>(kSecondPayload.begin(), kSecondPayload.end()),
            static_cast<std::uint16_t>(kSecondPayload.size()));

        const auto dut_mac = cfg.dut.mac;
        const std::string iface_str(iface);
        const std::uint32_t inject_ack =
            first_seg_seq +
            static_cast<std::uint32_t>(kFirstPayload.size());

        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_piggyback),
            [cfg, iface_str, dut_mac, local_port, remote_port,
             tester_snd, inject_ack, ack_drop]() {
                ::tc8::stimulus::TcpSegmentSpec data{};
                data.src_port = remote_port;
                data.dst_port = local_port;
                data.seq_num  = tester_snd;
                data.ack_num  = inject_ack;
                data.flags    = ::tc8::stimulus::kTcpFlagPsh
                              | ::tc8::stimulus::kTcpFlagAck;
                data.payload.assign(kTesterPayload.begin(),
                                    kTesterPayload.end());
                ::tc8::sce::tcp::emitTcpFrame(
                    cfg, iface_str, dut_mac, data,
                    /*initial_wait=*/std::chrono::milliseconds(0));
                (void)ack_drop;
            });
        (void)tester_fd;
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                                       return "pass";
            case State::Fail_no_first_data:                         return "fail:no_dut_first_data_segment";
            case State::Fail_dut_sent_second_segment_before_ack:    return "fail:dut_sent_second_segment_before_piggyback_inject";
            case State::Fail_no_piggyback:                          return "fail:no_dut_piggyback_segment_within_500ms";
            case State::Fail_wrong_piggyback_ack:                   return "fail:dut_piggyback_ack_num_does_not_acknowledge_tester_payload";
            default:                                                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsProcessing10SM, tcp_flags_processing_10)
