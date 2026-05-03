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

#include "tcp_acknowledgement_02_sm.h"

namespace tc8::sce::cases {

using TcpAcknowledgement02SM =
    ::SCE::Generated::tcp_acknowledgement_02::tcp_acknowledgement_02;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpAcknowledgement02SM>
    : TcpAnyBase<cases::TcpAcknowledgement02SM> {
    static constexpr std::string_view kCaseId       = "TCP_ACKNOWLEDGEMENT_02";
    static constexpr std::string_view kSpecSection  = "4.8.6.18";
    static constexpr std::string_view kDescription  =
        "DUT accepts an ACK piggybacked with the next transmit packet "
        "and replies with a pure ACK acknowledging the payload "
        "(RFC 793 §3.9 Event Processing).";

    static constexpr std::array<std::uint8_t, 4> kDutPayload = {
        0xDDU, 0xDDU, 0xDDU, 0xDDU};
    static constexpr std::array<std::uint8_t, 4> kTesterPayload = {
        0xC0U, 0xDEU, 0xCAU, 0xFEU};

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  =
            kBasicsActiveLocalPort  + kTcpAck02LocalOffset;
        const std::uint16_t remote_port =
            kBasicsActiveRemotePort + kTcpAck02LocalOffset;

        auto listener = driveActiveOpenEstablished(
            cfg, iface, cfg.arp.dut_real_mac,
            /*open_req_id=*/1, local_port, remote_port);
        const int tester_fd = listener.acceptOne();
        if (tester_fd < 0) return;

        sendSendTcpDataRequest(
            cfg, iface, cfg.arp.dut_real_mac,
            /*req_id=*/2, /*socket_id=*/1,
            kDutPayload.data(),
            static_cast<std::uint16_t>(kDutPayload.size()));
        std::this_thread::sleep_for(std::chrono::milliseconds(150));

        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (!seq_range.has_value()) {
            ::close(tester_fd);
            return;
        }

        const std::uint32_t injected_seq  = seq_range->snd_nxt;
        const std::uint32_t tester_paylen =
            static_cast<std::uint32_t>(kTesterPayload.size());
        c.expected_ack_num = injected_seq + tester_paylen;

        ::tc8::stimulus::TcpSegmentSpec data{};
        data.src_port = remote_port;
        data.dst_port = local_port;
        data.seq_num  = injected_seq;
        data.ack_num  = seq_range->rcv_nxt;
        data.flags    = ::tc8::stimulus::kTcpFlagPsh
                      | ::tc8::stimulus::kTcpFlagAck;
        data.payload.assign(kTesterPayload.begin(), kTesterPayload.end());
        emitTcpFrame(cfg, iface, cfg.arp.dut_real_mac, data,
                     /*initial_wait=*/std::chrono::milliseconds(0));
        (void)tester_fd;
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                       return "pass";
            case State::Fail_no_handshake_ack:      return "fail:no_dut_handshake_ack";
            case State::Fail_no_data_ack:           return "fail:no_dut_ack_to_piggyback_data";
            case State::Fail_wrong_ack_num:         return "fail:dut_ack_num_does_not_acknowledge_piggyback_payload";
            default:                                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpAcknowledgement02SM, tcp_acknowledgement_02)
