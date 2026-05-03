#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_connection_estab_01_sm.h"

namespace tc8::sce::cases {

using TcpConnectionEstab01SM =
    ::SCE::Generated::tcp_connection_estab_01::tcp_connection_estab_01;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpConnectionEstab01SM>
    : TcpAnyBase<cases::TcpConnectionEstab01SM> {
    static constexpr std::string_view kCaseId       = "TCP_CONNECTION_ESTAB_01";
    static constexpr std::string_view kSpecSection  = "4.8.6.15";
    static constexpr std::string_view kDescription  =
        "Single passive socket accepts SYNs from 3 distinct remote "
        "source ports and replies SYN,ACK on each (RFC 793 §3.4).";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        sendOpenTcpSocketPassiveRequest(
            cfg, iface, cfg.arp.dut_real_mac,
            /*req_id=*/1, kTcpConnEstab01ListenPort);
        std::this_thread::sleep_for(kTcpUtRpcWait);

        const std::array<std::uint16_t, 3> src_ports{
            kTcpConnEstab01TesterSrcPort1,
            kTcpConnEstab01TesterSrcPort2,
            kTcpConnEstab01TesterSrcPort3,
        };

        TesterAutoRstDrop rst_drop(cfg);

        for (auto src_port : src_ports) {
            ::tc8::stimulus::TcpSegmentSpec syn{};
            syn.src_port = src_port;
            syn.dst_port = kTcpConnEstab01ListenPort;
            syn.seq_num  = kTesterInitialSeq;
            syn.flags    = ::tc8::stimulus::kTcpFlagSyn;
            emitTcpFrame(cfg, iface, cfg.arp.dut_real_mac, syn,
                         /*initial_wait=*/std::chrono::milliseconds(0));
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        sendCloseTcpSocketRequest(cfg, iface, cfg.arp.dut_real_mac,
                                   /*req_id=*/2, /*socket_id=*/1);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                return "pass";
            case State::Fail_timeout_leg1:   return "fail:no_dut_synack_for_leg1";
            case State::Fail_timeout_leg2:   return "fail:no_dut_synack_for_leg2";
            case State::Fail_timeout_leg3:   return "fail:no_dut_synack_for_leg3";
            default:                         return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpConnectionEstab01SM, tcp_connection_estab_01)
