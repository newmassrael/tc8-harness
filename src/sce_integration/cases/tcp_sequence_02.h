#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_sequence_02_sm.h"

namespace tc8::sce::cases {

using TcpSequence02SM =
    ::SCE::Generated::tcp_sequence_02::tcp_sequence_02;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpSequence02SM>
    : TcpAnyBase<cases::TcpSequence02SM> {
    static constexpr std::string_view kCaseId       = "TCP_SEQUENCE_02";
    static constexpr std::string_view kSpecSection  = "4.8.6.17";
    static constexpr std::string_view kDescription  =
        "From SYN-SENT, DUT acknowledges tester ISN by emitting "
        "ACK with ack_num == tester_seq + 1 (RFC 793 §3.4).";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  =
            kBasicsActiveLocalPort + kTcpSequence02LocalOffset;
        const std::uint16_t remote_port =
            kBasicsActiveRemotePort + kTcpSequence02LocalOffset;

        // No tester listener: SEQUENCE_02 needs the tester-side
        // SYN+ACK to carry a custom Sequence Number, which a real
        // listener would replace with a kernel-chosen ISN. The
        // TesterAutoRstDrop suppresses the kernel's auto-RST against
        // the unbound (tester_ip, remote_port) tuple so the DUT-
        // emitted SYN is not race-killed before the snippet captures
        // it. The tester kernel never sees DUT's pure-ACK landing on
        // an unknown 4-tuple either; iptables still drops any auto-
        // RST it would emit.
        TesterAutoRstDrop rst_drop(cfg);

        auto syn_snippet =
            TcpFrameSnippet::forDutSyn(cfg, iface, local_port);

        sendOpenTcpSocketActiveRequest(
            cfg, iface, cfg.arp.dut_real_mac,
            /*open_req_id=*/1, local_port,
            cfg.ipv4.tester_ip, remote_port);
        std::this_thread::sleep_for(kTcpUtRpcWait);

        const auto dut_syn = syn_snippet.tryCapture(
            std::chrono::milliseconds(2000));
        if (!dut_syn) {
            sendCloseTcpSocketRequest(cfg, iface, cfg.arp.dut_real_mac,
                                       /*req_id=*/2, /*socket_id=*/1);
            return;
        }
        const std::uint32_t dut_isn = dut_syn->seq_num;

        ::tc8::stimulus::TcpSegmentSpec syn_ack{};
        syn_ack.src_port = remote_port;
        syn_ack.dst_port = local_port;
        syn_ack.seq_num  = kTesterInitialSeq;
        syn_ack.ack_num  = dut_isn + 1U;
        syn_ack.flags    = ::tc8::stimulus::kTcpFlagSyn
                         | ::tc8::stimulus::kTcpFlagAck;
        emitTcpFrame(cfg, iface, cfg.arp.dut_real_mac, syn_ack,
                     /*initial_wait=*/std::chrono::milliseconds(0));

        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        sendCloseTcpSocketRequest(cfg, iface, cfg.arp.dut_real_mac,
                                   /*req_id=*/2, /*socket_id=*/1);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:               return "pass";
            case State::Fail_wrong_ack_num: return "fail:dut_ack_num_does_not_acknowledge_tester_isn";
            case State::Fail_timeout:       return "fail:no_dut_ack_to_synack_within_listen_window";
            default:                        return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpSequence02SM, tcp_sequence_02)
