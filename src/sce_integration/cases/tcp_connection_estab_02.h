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

#include "tcp_connection_estab_02_sm.h"

namespace tc8::sce::cases {

using TcpConnectionEstab02SM =
    ::SCE::Generated::tcp_connection_estab_02::tcp_connection_estab_02;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpConnectionEstab02SM>
    : TcpAnyBase<cases::TcpConnectionEstab02SM> {
    static constexpr std::string_view kCaseId       = "TCP_CONNECTION_ESTAB_02";
    static constexpr std::string_view kSpecSection  = "4.8.6.15";
    static constexpr std::string_view kDescription  =
        "DUT opens 3 passive sockets and emits SYN,ACK on each "
        "received tester SYN (RFC 793 §3.4).";

    struct Leg {
        std::uint16_t listen_port;
        std::uint16_t tester_src_port;
        std::uint8_t  socket_id;
    };

    static void emitSyn(const ::tc8::TestConfig& cfg,
                        std::string_view iface,
                        const Leg& leg) {
        ::tc8::stimulus::TcpSegmentSpec syn{};
        syn.src_port = leg.tester_src_port;
        syn.dst_port = leg.listen_port;
        syn.seq_num  = ::tc8::sce::tcp::kTesterInitialSeq;
        syn.flags    = ::tc8::stimulus::kTcpFlagSyn;
        ::tc8::sce::tcp::emitTcpFrame(cfg, iface, cfg.dut.mac,
                                       syn,
                                       /*initial_wait=*/std::chrono::milliseconds(0));
    }

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::array<Leg, 3> legs{
            Leg{kTcpConnEstab02ListenPort1, kTcpConnEstab02TesterSrcPort1, 1U},
            Leg{kTcpConnEstab02ListenPort2, kTcpConnEstab02TesterSrcPort2, 2U},
            Leg{kTcpConnEstab02ListenPort3, kTcpConnEstab02TesterSrcPort3, 3U},
        };

        // Open 3 passive sockets (tc8-dut OpOpenTcpSocket increments
        // socket_id internally; we pass req_id 1/2/3 to keep the UT
        // RPC matching deterministic per leg).
        for (std::uint8_t i = 0; i < legs.size(); ++i) {
            sendOpenTcpSocketPassiveRequest(
                cfg, iface, cfg.dut.mac,
                /*req_id=*/static_cast<std::uint8_t>(i + 1U),
                legs[i].listen_port);
            std::this_thread::sleep_for(kTcpUtRpcWait);
        }

        TesterAutoRstDrop rst_drop(cfg);

        for (const auto& leg : legs) {
            emitSyn(cfg, iface, leg);
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }

        // Settle so DUT SYN,ACKs all land in pcap before close kicks
        // the listeners and any stray tester segments could race.
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        for (std::uint8_t i = 0; i < legs.size(); ++i) {
            sendCloseTcpSocketRequest(
                cfg, iface, cfg.dut.mac,
                /*req_id=*/static_cast<std::uint8_t>(i + 4U),
                legs[i].socket_id);
        }
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

TC8_REGISTER_CASE(::tc8::sce::cases::TcpConnectionEstab02SM, tcp_connection_estab_02)
