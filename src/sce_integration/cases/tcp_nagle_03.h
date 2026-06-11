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

#include "tcp_nagle_03_sm.h"

namespace tc8::sce::cases {

using TcpNagle03SM = ::SCE::Generated::tcp_nagle_03::tcp_nagle_03;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpNagle03SM>
    : TcpAnyBase<cases::TcpNagle03SM> {
    static constexpr std::string_view kCaseId       = "TCP_NAGLE_03";
    static constexpr std::string_view kSpecSection  = "4.8.6.13";
    static constexpr std::string_view kDescription  =
        "DUT MUST implement Nagle: small SEND (ssz) is buffered while "
        "outstanding data is unacked; one further SEND that fills MSS "
        "triggers a single aggregate segment of size MSS (RFC 1122 "
        "§4.2.3.4).";

    static constexpr std::array<std::uint8_t, 10> kFirstPayload = {
        'N','A','G','L','E','3','-','S','1','S'};
    static constexpr std::array<std::uint8_t, 10> kSecondPayload = {
        'N','A','G','L','E','3','-','S','2','M'};
    // 3rd send fills MSS - 10 (= 1450 B) so total buffered (seg 2 +
    // seg 3) equals the 1460 B effective send MSS on a 1500 B veth.
    static constexpr std::uint16_t kThirdPayloadLen = 1450U;
    static constexpr std::uint8_t  kThirdPattern    = 0xA3U;

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  =
            kBasicsActiveLocalPort  + kTcpNagle03LocalOffset;
        const std::uint16_t remote_port =
            kBasicsActiveRemotePort + kTcpNagle03LocalOffset;

        auto listener = driveActiveOpenEstablished(
            cfg, iface, cfg.dut.mac,
            /*open_req_id=*/1, local_port, remote_port);
        const int tester_fd = listener.acceptOne();
        if (tester_fd < 0) return;

        const auto seq_range_pre = queryTcpSeqRange(tester_fd);
        if (!seq_range_pre.has_value()) {
            ::close(tester_fd);
            return;
        }
        c.expected_ack_num = seq_range_pre->rcv_nxt;

        auto ack_drop = std::make_shared<TesterAutoAckDrop>(cfg);
        (void)ack_drop;

        sendSendTcpDataRequest(
            cfg, iface, cfg.dut.mac,
            /*req_id=*/2, /*socket_id=*/1,
            kFirstPayload.data(),
            static_cast<std::uint16_t>(kFirstPayload.size()));
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        sendSendTcpDataRequest(
            cfg, iface, cfg.dut.mac,
            /*req_id=*/3, /*socket_id=*/1,
            kSecondPayload.data(),
            static_cast<std::uint16_t>(kSecondPayload.size()));
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        sendSendTcpDataPatternRequest(
            cfg, iface, cfg.dut.mac,
            /*req_id=*/4, /*socket_id=*/1,
            kThirdPattern, kThirdPayloadLen);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        (void)tester_fd;
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                                                   return "pass";
            case State::Fail_no_first_data:                                     return "fail:no_dut_first_data_segment";
            case State::Fail_dut_released_small_segment_before_aggregate:       return "fail:dut_released_small_segment_before_aggregate_nagle_violation";
            case State::Fail_no_aggregate:                                      return "fail:no_dut_aggregate_segment_after_mss_fill";
            default:                                                            return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpNagle03SM, tcp_nagle_03)
