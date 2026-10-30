#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string_view>
#include <thread>

#include <sys/socket.h>

#include "sce_integration/cases/_tcp_seam_time_wait_prelude.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/tcp_captured.h"
#include "sce_integration/test_config.h"
#include "stimulus/tcp_segment_builder.h"

// The body the iterations of TCP_FLAGS_PROCESSING_09 share. The case asks one question of a DUT
// that has received a FIN and is waiting to close (CLOSE-WAIT, CLOSING or LAST-ACK): given a
// duplicate of that FIN carrying the ACK flag, does it keep its state. The iterations differ in
// the state the DUT is parked in and in the ACK number the duplicate carries, so the duplicate
// is built once and each state brings its own prelude.
//
// Every active OPEN runs through driveSeamActiveOpen, the CLOSING DUT CLOSE through
// driveSeamCloseToClosing and the LAST-ACK DUT CLOSE through closeTcp, so the case runs
// unchanged on whichever backend --dut-control selected. The tester-side duplicate FIN is raw
// injected and stays case-owned.

namespace tc8::sce::cases {

enum class Processing09State {
    // The DUT has ACKed the tester's FIN and has not closed (the first iteration).
    kCloseWait,
    // Both sides have sent a FIN and the DUT's has not been acknowledged (the second iteration).
    kClosing,
    // The DUT closed from CLOSE-WAIT and its FIN has not been acknowledged (the third
    // iteration).
    kLastAck,
};

// A FIN carrying the ACK flag. Each iteration replays the tester's original FIN, so its SEQ is
// below the DUT's rcv_nxt: old data the DUT drops or quick-ACKs.
inline void emitDupFinAck(const ::tc8::TestConfig &cfg, std::string_view iface,
                          std::uint16_t src_port, std::uint16_t dst_port, std::uint32_t seq_value,
                          std::uint32_t ack_value) {
    ::tc8::stimulus::TcpSegmentSpec dup{};
    dup.src_port = src_port;
    dup.dst_port = dst_port;
    dup.seq_num = seq_value;
    dup.ack_num = ack_value;
    dup.flags = ::tc8::stimulus::kTcpFlagFin | ::tc8::stimulus::kTcpFlagAck;
    ::tc8::sce::tcp::emitTcpFrame(cfg, iface, cfg.dut.mac, dup,
                                  /*initial_wait=*/std::chrono::milliseconds(0));
}

// One iteration. `local_offset` is its port-quad offset; the three sit clear of the active-OPEN
// cluster reservations of the other TCP cases.
inline void driveProcessing09Iteration(::tc8::sce::IDutControl &dut, const ::tc8::TestConfig &cfg,
                                       std::string_view iface, std::uint16_t local_offset,
                                       Processing09State state) {
    using namespace ::tc8::sce::tcp;

    const std::uint16_t local_port = kBasicsActiveLocalPort + local_offset;
    const std::uint16_t remote_port = kBasicsActiveRemotePort + local_offset;

    // The states that wait for an ACK of the DUT's own FIN need the tester kernel's auto-ACK held
    // back, or the DUT leaves the state under test.
    std::optional<TesterAutoAckDrop> ack_drop;
    if (state != Processing09State::kCloseWait) {
        ack_drop.emplace(cfg);
    }

    auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
    const int tester_fd = open.listener.acceptOne();
    if (tester_fd < 0 || !open.conn) {
        silentlyCloseTesterFd(tester_fd);
        return;
    }

    switch (state) {
        case Processing09State::kCloseWait: {
            ::shutdown(tester_fd, SHUT_WR);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            const auto seq_range = queryTcpSeqRange(tester_fd);
            if (seq_range.has_value()) {
                // Replay the original tester FIN: seq = snd_nxt - 1 (the FIN consumed +1 to
                // advance snd_nxt). ack is valid (rcv_nxt = the DUT's post-handshake snd_nxt; the
                // DUT was never closed, so it has sent no FIN). DUT.snd_nxt is unchanged, so the
                // ACK is a duplicate ACK.
                emitDupFinAck(cfg, iface, remote_port, local_port, seq_range->snd_nxt - 1U,
                              seq_range->rcv_nxt);
            }
            break;
        }
        case Processing09State::kClosing: {
            const auto info = driveSeamCloseToClosing(dut, cfg, iface, tester_fd,
                                                      open.conn->socket, local_port, remote_port);
            if (info.ok) {
                // Replay the helper-injected FIN: seq = tester_seq_post_fin - 1. ack =
                // tester_ack_post_fin - 1, acceptable but it does NOT acknowledge the DUT's FIN,
                // so the DUT stays in CLOSING.
                emitDupFinAck(cfg, iface, remote_port, local_port, info.tester_seq_post_fin - 1U,
                              info.tester_ack_post_fin - 1U);
            }
            break;
        }
        case Processing09State::kLastAck: {
            ::shutdown(tester_fd, SHUT_WR);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            // The DUT's close takes it CLOSE-WAIT -> LAST-ACK; the held auto-ACK keeps it there.
            dut.tcpControl()->closeTcp(open.conn->socket);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            const auto seq_range = queryTcpSeqRange(tester_fd);
            if (seq_range.has_value()) {
                // Replay the original tester FIN: seq = snd_nxt - 1. ack = rcv_nxt - 1,
                // acceptable per RFC 793 §3.4 but it does NOT acknowledge the DUT's FIN, so the
                // DUT stays in LAST-ACK.
                emitDupFinAck(cfg, iface, remote_port, local_port, seq_range->snd_nxt - 1U,
                              seq_range->rcv_nxt - 1U);
            }
            break;
        }
    }
    silentlyCloseTesterFd(tester_fd);
}

}  // namespace tc8::sce::cases
