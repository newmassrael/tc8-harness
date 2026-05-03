#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_closing_13_sm.h"

namespace tc8::sce::cases {

using TcpClosing13SM = ::SCE::Generated::tcp_closing_13::tcp_closing_13;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpClosing13SM>
    : TcpAnyBase<cases::TcpClosing13SM> {
    static constexpr std::string_view kCaseId       = "TCP_CLOSING_13";
    static constexpr std::string_view kSpecSection  = "4.8.6.8";
    static constexpr std::string_view kDescription  =
        "TCP in CLOSED state MUST ignore a RST control message "
        "(RFC 793 §3.9 p65 Event Processing)";

    // Single iteration. Tester raw-injects one RST at the
    // (kBasicsTesterPort + 80, kBasicsClosedPort) 4-tuple — DUT has
    // no socket on the closed port, so Linux's tcp_v4_rcv falls into
    // `no_tcp_socket:` which discards an incoming RST without emitting
    // any response. SCXML's 3 s absence window observes the silence.
    //
    // Tester source +80 reserved for the §4.8.6.8 closed-port cluster
    // (clear of FP_08 phase 2's +71 and FP_05/_02's +72..+76). No
    // active-OPEN, no passive listen, no kernel state on either
    // side — RstDrop/AckDrop scaffolding not needed.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        ::tc8::stimulus::TcpSegmentSpec rst{};
        rst.src_port = kBasicsTesterPort + 80U;
        rst.dst_port = kBasicsClosedPort;
        rst.seq_num  = kTesterInitialSeq;
        rst.ack_num  = 0U;
        rst.flags    = ::tc8::stimulus::kTcpFlagRst;
        emitTcpFrame(cfg, iface, cfg.arp.dut_real_mac, rst,
                     /*initial_wait=*/std::chrono::milliseconds(0));
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                       return "pass";
            case State::Fail_unexpected_response:   return "fail:dut_emitted_response_to_rst_in_closed";
            default:                                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpClosing13SM, tcp_closing_13)
