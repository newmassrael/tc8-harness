#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string_view>
#include <thread>
#include <unistd.h>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_nagle_02_sm.h"

namespace tc8::sce::cases {

using TcpNagle02SM = ::SCE::Generated::tcp_nagle_02::tcp_nagle_02;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpNagle02SM>
    : TcpAnyBase<cases::TcpNagle02SM> {
    static constexpr std::string_view kCaseId       = "TCP_NAGLE_02";
    static constexpr std::string_view kSpecSection  = "4.8.6.13";
    static constexpr std::string_view kDescription  =
        "DUT MUST implement Nagle: with outstanding unacknowledged data "
        "the second small SEND is buffered; the buffered segment is "
        "released only after the first segment is ACKed (RFC 1122 "
        "§4.2.3.4).";

    static constexpr std::array<std::uint8_t, 10> kFirstPayload = {
        'N','A','G','L','E','-','S','E','G','1'};
    static constexpr std::array<std::uint8_t, 10> kSecondPayload = {
        'N','A','G','L','E','-','S','E','G','2'};

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut,
                         IStimulusScheduler& scheduler) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  =
            kBasicsActiveLocalPort  + kTcpNagle02LocalOffset;
        const std::uint16_t remote_port =
            kBasicsActiveRemotePort + kTcpNagle02LocalOffset;

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
        c.expected_ack_num = first_seg_seq;

        auto ack_drop = std::make_shared<TesterAutoAckDrop>(cfg);

        seamSendTcp(dut, open.conn->socket, kFirstPayload);
        // Space the second SEND past seg1's RTO so the small segment is held by
        // Nagle rather than escaping at the RTO boundary — see
        // kTcpSeamInterSendRtoClearGap.
        std::this_thread::sleep_for(kTcpSeamInterSendRtoClearGap);

        seamSendTcp(dut, open.conn->socket, kSecondPayload);

        const auto dut_mac = cfg.dut.mac;
        const std::string iface_str(iface);
        const std::uint32_t ack_num =
            first_seg_seq +
            static_cast<std::uint32_t>(kFirstPayload.size());

        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_second_data),
            [cfg, iface_str, dut_mac, local_port, remote_port,
             tester_snd, ack_num, ack_drop]() {
                ::tc8::stimulus::TcpSegmentSpec ack_seg{};
                ack_seg.src_port = remote_port;
                ack_seg.dst_port = local_port;
                ack_seg.seq_num  = tester_snd;
                ack_seg.ack_num  = ack_num;
                ack_seg.flags    = ::tc8::stimulus::kTcpFlagAck;
                ::tc8::sce::tcp::emitTcpFrame(
                    cfg, iface_str, dut_mac, ack_seg,
                    /*initial_wait=*/std::chrono::milliseconds(0));
                (void)ack_drop;
            });
        (void)tester_fd;
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                                       return "pass";
            case State::Fail_no_first_data:                         return "fail:no_dut_first_data_segment";
            case State::Fail_dut_sent_second_segment_before_ack:    return "fail:dut_sent_second_segment_before_ack_nagle_violation";
            case State::Fail_no_second_data:                        return "fail:no_dut_second_data_segment_after_ack";
            default:                                                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpNagle02SM, tcp_nagle_02)
