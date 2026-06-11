#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"

#include "tcp_basics_02_sm.h"

namespace tc8::sce::cases {

using TcpBasics02SM = ::SCE::Generated::tcp_basics_02::tcp_basics_02;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpBasics02SM>
    : TcpAnyBase<cases::TcpBasics02SM> {
    static constexpr std::string_view kCaseId       = "TCP_BASICS_02";
    static constexpr std::string_view kSpecSection  = "4.8.6.1";
    static constexpr std::string_view kDescription  =
        "TCP MUST move on to ESTABLISHED state after receiving ACK in "
        "SYN-RCVD state (RFC 793 §3.2 p23 Terminology)";

    // Spec Test Procedure (v3.0 p281-p300.txt:428):
    //   1. TESTER: Send a SYN   — kernel connect() emits SYN.
    //   2. DUT:    Send SYN,ACK — observed on pcap.
    //   3. TESTER: Send an ACK  — kernel completes the handshake.
    //   4. TESTER: Verify DUT at ESTABLISHED — UT OpQueryTcpEstablished.
    //
    // The UT query runs synchronously in the stimulus so its result
    // is embedded in `c.ut_established` before the SCXML reads it on
    // the first tcp_observed edge (the kernel-buffered SYN,ACK).
    //
    // Socket fd is kept open across the query so tc8-dut's accepted
    // connection doesn't race a tester-side RST. Close happens in
    // the UT OpCloseTcpSocket (tc8-dut tears down the listener + the
    // accepted fd).
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);
        sendOpenTcpSocketPassiveRequest(
            cfg, iface, cfg.dut.mac,
            /*req_id=*/1, kBasicsListenPort);
        std::this_thread::sleep_for(kTcpUtRpcWait);

        int client_fd = -1;
        connectToDutTcp(cfg, kBasicsListenPort, TcpPostClose::kKeepOpen,
                         &client_fd);

        // Query AFTER the 3-way handshake has completed. Linux kernel
        // TCP sets skb->sk->sk_state = TCP_ESTABLISHED on the listen
        // socket's accepted fd synchronously inside the ACK-processing
        // path, and accept() returns immediately once the entry is in
        // the accept queue. 50 ms absorbs the worker-netns scheduler
        // and the accept-thread poll tick without burning wall time.
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        c.ut_established = queryTcpEstablishedSync(
            cfg, /*req_id=*/3, /*socket_id=*/1);

        if (client_fd >= 0) ::close(client_fd);
        sendCloseTcpSocketRequest(
            cfg, iface, cfg.dut.mac,
            /*req_id=*/2, /*socket_id=*/1);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                   return "pass";
            case State::Fail_not_established:   return "fail:dut_did_not_reach_established";
            case State::Fail_timeout:           return "fail:no_dut_syn_ack_within_listen_window";
            default:                            return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpBasics02SM, tcp_basics_02)
