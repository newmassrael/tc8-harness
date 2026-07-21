#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam_passive_open.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
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
    static constexpr std::string_view kDescription  =
        "Single passive socket accepts SYNs from 3 distinct remote "
        "source ports and replies SYN,ACK on each (RFC 793 §3.4).";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        // LISTEN via driveSeamListen (ITcpControl::listenTcp, listen-only) so the
        // case runs on whichever backend `--dut-control` selected; the three
        // raw-inject SYNs and the SYN,ACK observations stay tester-side.
        const auto listen = driveSeamListen(dut, kTcpConnEstab01ListenPort);
        if (!listen) return;

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
            emitTcpFrame(cfg, iface, cfg.dut.mac, syn,
                         /*initial_wait=*/std::chrono::milliseconds(0));
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        dut.tcpControl()->closeTcp(*listen);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpConnectionEstab01SM, tcp_connection_estab_01)
