#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <vector>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

// Shared prelude for the two §4.8.6.4 TCP_CALL_RECEIVE_05 must-not-respond-in-CW _NEG
// variants (RST via kTcpSynthRstOnDisruptive, FIN via kTcpSynthFinOnDisruptive). Both drive
// the DUT through an active OPEN to ESTABLISHED and inject the same PSH+FIN+ACK data segment
// the positive uses (the EST->CW trigger), with the synthesis flavor armed BEFORE the inject
// so the netif input hook fabricates the prohibited RST / FIN+ACK as that disruptive segment
// arrives. The variants differ only in the armed flavor and the per-case active-OPEN port
// offset, so the prelude is factored here rather than duplicated across the two traits.
namespace tc8::sce::cases::call_receive_05_neg {

// 16-byte payload mirroring the positive (0xC3) so a stray data segment in pcap is
// attributable to the CALL_RECEIVE_05 family.
inline constexpr std::uint16_t kPayloadLen = 16U;

inline void driveCwAndArm(::tc8::sce::IDutControl& dut,
                          const ::tc8::TestConfig& cfg,
                          std::string_view iface,
                          std::uint8_t flavor,
                          std::uint16_t port_offset) {
    using namespace ::tc8::sce::tcp;
    std::this_thread::sleep_for(kTcpUtBootWait);

    const std::uint16_t local_port  = kBasicsActiveLocalPort  + port_offset;
    const std::uint16_t remote_port = kBasicsActiveRemotePort + port_offset;

    auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
    const int tester_fd = open.listener.acceptOne();
    if (tester_fd < 0 || !open.conn) return;

    const auto seq_range = queryTcpSeqRange(tester_fd);
    if (!seq_range.has_value()) {
        silentlyCloseTesterFd(tester_fd);
        return;
    }

    // Per-phase arm before the disruptive PSH+FIN+ACK. The settle gap lets the raw-injected
    // arm reach the DUT UT thread before the segment reaches the netif input hook.
    emitIngressFlavorArmMidStream(cfg, iface, flavor);
    std::this_thread::sleep_for(kFlavorArmSettle);

    // The EST->CW trigger: a PSH+FIN+ACK carrying 16 B of data. ack=rcv_nxt acks the
    // handshake third-leg; seq=snd_nxt is the tester's next byte. The DUT processes the
    // data+FIN into CLOSE-WAIT, but the armed hook fabricates the prohibited RST / FIN+ACK
    // on the inbound segment first (synthesis runs before lwIP sees the frame).
    const std::vector<std::uint8_t> payload(kPayloadLen, 0xC3U);
    ::tc8::stimulus::TcpSegmentSpec fin_data{};
    fin_data.src_port = remote_port;
    fin_data.dst_port = local_port;
    fin_data.seq_num  = seq_range->snd_nxt;
    fin_data.ack_num  = seq_range->rcv_nxt;
    fin_data.flags    = ::tc8::stimulus::kTcpFlagAck
                      | ::tc8::stimulus::kTcpFlagPsh
                      | ::tc8::stimulus::kTcpFlagFin;
    fin_data.payload  = payload;
    emitTcpFrame(cfg, iface, cfg.dut.mac, fin_data,
                 /*initial_wait=*/std::chrono::milliseconds(0));

    std::this_thread::sleep_for(kSynthRstObserveHold);

    // Silent tester disposal — no tester FIN/RST that could itself confuse the observation.
    silentlyCloseTesterFd(tester_fd);
}

}  // namespace tc8::sce::cases::call_receive_05_neg
