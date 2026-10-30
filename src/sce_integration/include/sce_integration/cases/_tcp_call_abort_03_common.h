#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>

#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/tcp_pilot_common.h"
#include "sce_integration/test_config.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

// What the three iterations of TCP_CALL_ABORT_03 share. Each iteration parks the DUT in a
// different closing state and has the DUT-side application abort the connection; the
// procedure that reaches the state differs per iteration and stays in the iteration's
// header. Two steps are the same in all of them and live here: the abort that ends an
// iteration, and the verify-probe ACK that proves the connection is gone.

namespace tc8::sce::cases {

// The abort every iteration ends on, then the release of the tester's socket.
// `abortTcp`'s result is not read here: the DUT-control decorator every backend is built
// inside records an abort the DUT did not perform as an unperformed stimulus, which turns
// the iteration inconclusive instead of grading the tester's request (dut_call_intent.h).
// The 150 ms gives the abortive close time to reach the wire before the tester fd is
// disposed; silentlyCloseTesterFd frees the 4-tuple without emitting a FIN.
inline void abortCallAbort03Socket(::tc8::sce::ITcpControl &tcp, ::tc8::sce::DutSocket sock,
                                   int tester_fd) {
    tcp.abortTcp(sock);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    ::tc8::sce::tcp::silentlyCloseTesterFd(tester_fd);
}

// Verify-probe ACK on entry to the verify_rst state. The probe arrives after the
// prelude+abort settle window, so the closed-port RST it elicits maps cleanly to the spec's
// "DUT moved to CLOSED" assertion. Same scheduleAfterStateEntry shape as TCP_CLOSING_03 /
// FLAGS_PROCESSING_02.
inline void scheduleCallAbort03VerifyProbe(::tc8::sce::IStimulusScheduler &scheduler,
                                           int verify_state, const ::tc8::TestConfig &cfg,
                                           std::string_view iface, std::uint16_t port_offset) {
    using namespace ::tc8::sce::tcp;
    const std::uint16_t local_port = kBasicsActiveLocalPort + port_offset;
    const std::uint16_t remote_port = kBasicsActiveRemotePort + port_offset;
    const std::array<std::uint8_t, 6> dut_mac = cfg.dut.mac;
    scheduler.scheduleAfterStateEntry(
        verify_state, [iface_copy = std::string(iface), cfg, dut_mac, local_port, remote_port]() {
            ::tc8::stimulus::TcpSegmentSpec ack{};
            ack.src_port = remote_port;
            ack.dst_port = local_port;
            ack.seq_num = kTesterInitialSeq + 100U;
            ack.ack_num = 0U;
            ack.flags = ::tc8::stimulus::kTcpFlagAck;
            ::tc8::sce::tcp::emitTcpFrame(cfg, iface_copy, dut_mac, ack,
                                          /*initial_wait=*/std::chrono::milliseconds(0));
        });
}

}  // namespace tc8::sce::cases
