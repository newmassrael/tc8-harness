#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"

#include "tcp_basics_06_sm.h"

namespace tc8::sce::cases {

using TcpBasics06SM = ::SCE::Generated::tcp_basics_06::tcp_basics_06;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpBasics06SM>
    : TcpAnyBase<cases::TcpBasics06SM> {
    static constexpr std::string_view kCaseId       = "TCP_BASICS_06";
    static constexpr std::string_view kSpecSection  = "4.8.6.1";
    static constexpr std::string_view kDescription  =
        "TCP in CLOSED state MUST send a SYN on an active OPEN call "
        "(RFC 793 §3.2 p23 Terminology)";

    // Spec Test Procedure (v3.0 p281-p300.txt:558):
    //   1. TESTER: Cause DUT app to issue active OPEN — UT
    //              OpOpenTcpSocket(Active).
    //   2. DUT:    Send a SYN — observed on pcap.
    //
    // Mechanism: the tester first arms an auxiliary kernel listener on
    // `kBasicsActiveRemotePort` so the DUT's outbound SYN reaches a
    // real receiver instead of the tester-kernel's RST-on-closed-port
    // path. The Active OpOpen request then spawns the DUT's connect()
    // worker, which emits the SYN observed by SCXML.
    //
    // Stimulus orders the listener bind BEFORE the UT request — the
    // DUT's SYN may follow the OpOpen confirmation by single-digit
    // milliseconds, so a listener that lands AFTER the SYN would race-
    // lose to a tester-kernel RST and the spec-assertion edge would
    // never fire (or, worse, the kernel's RST itself would arrive first
    // and would not match the SYN-only pass guard's flag conjunct).
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        // RAII listener (move-returned from the helper); the DUT's SYN
        // is on the wire by the time this returns, so the SCXML arms
        // its listen window with the spec-asserted edge already in
        // pcap's kernel buffer.
        auto listener = driveActiveOpenEstablished(
            cfg, iface, cfg.arp.dut_real_mac,
            /*open_req_id=*/1,
            kBasicsActiveLocalPort  + kTcpBasics06LocalOffset,
            kBasicsActiveRemotePort + kTcpBasics06LocalOffset);
        (void)listener;

        sendCloseTcpSocketRequest(
            cfg, iface, cfg.arp.dut_real_mac,
            /*req_id=*/2, /*socket_id=*/1);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:          return "pass";
            case State::Fail_timeout:  return "fail:no_dut_syn_within_listen_window";
            default:                   return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpBasics06SM, tcp_basics_06)
