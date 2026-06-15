#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam_passive_open.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_control_flags_08_sm.h"

namespace tc8::sce::cases {

using TcpControlFlags08SM =
    ::SCE::Generated::tcp_control_flags_08::tcp_control_flags_08;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpControlFlags08SM>
    : TcpAnyBase<cases::TcpControlFlags08SM> {
    static constexpr std::string_view kCaseId       = "TCP_CONTROL_FLAGS_08";
    static constexpr std::string_view kSpecSection  = "4.8.6.19";
    static constexpr std::string_view kDescription  =
        "Recovery from old duplicate SYN: DUT in LISTEN replies SYN,ACK "
        "to a stale SYN, consumes a tester-injected RST with believable "
        "seq, returns to LISTEN, and replies SYN,ACK to a fresh SYN "
        "(RFC 793 §3.4 figure 9, p33).";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        // LISTEN via driveSeamListen (ITcpControl::listenTcp, listen-only) so
        // the case runs on whichever backend `--dut-control` selected; the
        // stale-SYN / recovery-RST / fresh-SYN injects stay tester-side.
        const auto listen = driveSeamListen(dut, kTcpControlFlags08ListenPort);
        if (!listen) return;

        // Suppress tester-kernel auto-RST against DUT-emitted SYN,ACK
        // for the entire stimulus — the raw-inject 4-tuple has no
        // tester-side socket, so the kernel would otherwise emit an
        // RST that races the test SYN+RST stimulus and aborts the
        // embryonic handshake before the spec-asserted sequence.
        // shared_ptr keeps the rule alive across stimulus return.
        auto rst_drop = std::make_shared<TesterAutoRstDrop>(cfg);

        // Phase 1 — old duplicate SYN.
        ::tc8::stimulus::TcpSegmentSpec syn1{};
        syn1.src_port = kTcpControlFlags08TesterSrcPort;
        syn1.dst_port = kTcpControlFlags08ListenPort;
        syn1.seq_num  = kTcpControlFlags08Seq1;
        syn1.flags    = ::tc8::stimulus::kTcpFlagSyn;
        emitTcpFrame(cfg, iface, cfg.dut.mac, syn1,
                     /*initial_wait=*/std::chrono::milliseconds(0));

        // Settle so the DUT egress SYN,ACK is in pcap and the
        // listener has reached SYN-RECEIVED before the recovery RST
        // arrives. 500 ms covers the DUT tcp_v4_rcv of the stale SYN +
        // SYN,ACK emission + scheduler jitter on a busy worker (the
        // passive listen itself already completed in driveSeamListen).
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        // Phase 1 recovery — RST with believable seq. Spec text:
        // "Send SYN with RST flag set with Sequence Number equal to
        // <SEQ1 + 1>". Linux's RST handling in SYN-RECEIVED matches
        // when seq == rcv_nxt (== SEQ1+1) per RFC 5961 §3.2 — DUT
        // aborts the embryonic connection and the passive listener
        // returns to LISTEN. The SYN bit is set per literal spec
        // text; Linux's tcp_validate_incoming sees RST and short-
        // circuits to tcp_reset regardless of the SYN bit.
        ::tc8::stimulus::TcpSegmentSpec rst{};
        rst.src_port = kTcpControlFlags08TesterSrcPort;
        rst.dst_port = kTcpControlFlags08ListenPort;
        rst.seq_num  = kTcpControlFlags08Seq1 + 1U;
        rst.flags    = ::tc8::stimulus::kTcpFlagSyn
                     | ::tc8::stimulus::kTcpFlagRst;
        emitTcpFrame(cfg, iface, cfg.dut.mac, rst,
                     /*initial_wait=*/std::chrono::milliseconds(0));

        std::this_thread::sleep_for(std::chrono::milliseconds(300));

        // Phase 2 — fresh SYN with new ISN. Same 4-tuple; the DUT
        // listener is back in LISTEN so accept succeeds.
        ::tc8::stimulus::TcpSegmentSpec syn2{};
        syn2.src_port = kTcpControlFlags08TesterSrcPort;
        syn2.dst_port = kTcpControlFlags08ListenPort;
        syn2.seq_num  = kTcpControlFlags08Seq2;
        syn2.flags    = ::tc8::stimulus::kTcpFlagSyn;
        emitTcpFrame(cfg, iface, cfg.dut.mac, syn2,
                     /*initial_wait=*/std::chrono::milliseconds(0));

        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        dut.tcpControl()->closeTcp(*listen);
        (void)rst_drop;
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpControlFlags08SM, tcp_control_flags_08)
