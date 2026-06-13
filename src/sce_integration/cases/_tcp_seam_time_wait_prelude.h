#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <unistd.h>

#include <netinet/tcp.h>

#include "sce_integration/cases/_tcp_seam_active_open.h"  // driveSeamActiveOpen
#include "sce_integration/dut_control.h"                  // IDutControl, DutSocket
#include "sce_integration/tcp_pilot_common.h"             // TcpTimeWaitInfo, tester-side helpers
#include "sce_integration/test_config.h"
#include "stimulus/tcp_segment_builder.h"                 // TcpSegmentSpec, kTcpFlag*

namespace tc8::sce::tcp {

// Tier-2 seam counterparts of the TIME-WAIT prelude helpers in
// tcp_pilot_common.h (driveTcpToTimeWaitFw2 / driveCloseToTimeWaitClosing).
// Same wire choreography; the ONLY difference is the DUT-control surface — the
// active OPEN routes through `driveSeamActiveOpen` and the DUT CLOSE through
// `ITcpControl::closeTcp` instead of the opcode Upper Tester directly, so a case
// built on these runs unchanged on whichever backend `--dut-control` selected
// (opcode UT or AUTOSAR testability) — the Tier-2 North Star
// (claudedocs/testability_seam_tier2_design.md).
//
// Lives in its own header (not tcp_pilot_common.h, which ~113 TCP TUs share and
// must not take on dut_control.h) — same rationale as _tcp_seam_active_open.h.
// The tester-side mechanics (the SEQ-range snapshot, the raw-inject FIN/ACK
// pair, the TesterAutoAckDrop iptables suppression, the TCP_REPAIR silent
// close) stay in tcp_pilot_common.h and are reused verbatim: only the DUT
// control verbs move onto the seam. Migrated TIME-WAIT cases thus prove the
// seam carries the full CLOSE-side lifecycle, not just OPEN + data.

// Seam counterpart of `driveTcpToTimeWaitFw2`: drive the DUT
// ESTABLISHED -> FIN-WAIT-2 -> TIME-WAIT (DUT CLOSE emits FIN, the tester
// kernel auto-ACKs it into FIN-WAIT-2, then a graceful tester shutdown(WR)
// completes the close). Self-contained: it performs its own seam active OPEN.
// Needs no iface/dut_mac — its body raw-injects nothing; the post-2*MSL FIN
// replay is the CALLER's, on the returned seq/ack base. Returns ok=false on a
// failed open (no tester connection accepted) or any local syscall failure.
inline TcpTimeWaitInfo driveSeamTimeWaitFw2(::tc8::sce::IDutControl &dut,
                                            const ::tc8::TestConfig &cfg,
                                            std::uint16_t local_port,
                                            std::uint16_t remote_port) {
    auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
    const int tester_fd = open.listener.acceptOne();
    if (tester_fd < 0) return {};

    if (open.conn) dut.tcpControl()->closeTcp(open.conn->socket);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    const auto seq_pre_fin = queryTcpSeqRange(tester_fd);
    if (!seq_pre_fin.has_value()) {
        ::close(tester_fd);
        return {};
    }

    ::shutdown(tester_fd, SHUT_WR);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    ::close(tester_fd);

    TcpTimeWaitInfo info{};
    info.ok                  = true;
    // Pre-FIN snd_nxt = ISN_t + 1 (post-handshake, no data sent). After the
    // kernel emits FIN at shutdown(WR), snd_nxt advances by 1 (FIN consumes one
    // sequence number) -> ISN_t + 2.
    info.tester_seq_post_fin = seq_pre_fin->snd_nxt + 1U;
    // rcv_nxt at query time already reflects the consumed DUT FIN (= ISN_d + 2).
    info.tester_ack_post_fin = seq_pre_fin->rcv_nxt;
    return info;
}

// Seam counterpart of `driveCloseToTimeWaitClosing`: drive the DUT into
// TIME-WAIT via the CLOSING path. The caller has already established the
// connection through the seam and owns `tester_fd` (the accepted tester-side
// socket) and `dut_socket` (the DUT's connected socket, from the seam open's
// DutConnection). The helper issues the DUT CLOSE through `closeTcp` and
// consumes `tester_fd` (closed on every path: TCP_REPAIR-silent on success,
// plain ::close on the SEQ-range-failure path). The raw-inject FIN/ACK
// choreography is identical to the opcode helper — see its block comment in
// tcp_pilot_common.h for the per-step RFC 793 §3.9 rationale.
//
// `iface` is still required: the FIN/ACK pair is a tester-side raw inject
// (emitTcpFrame), which is harness infrastructure, not DUT control. `dut_mac`
// is taken from `cfg.dut.mac` (every opcode-helper caller passed exactly that).
inline TcpTimeWaitInfo driveSeamCloseToTimeWaitClosing(::tc8::sce::IDutControl &dut,
                                                       const ::tc8::TestConfig &cfg,
                                                       std::string_view iface,
                                                       int tester_fd,
                                                       ::tc8::sce::DutSocket dut_socket,
                                                       std::uint16_t local_port,
                                                       std::uint16_t remote_port) {
    auto silent_close = [tester_fd]() {
        if (tester_fd < 0) return;
        int repair_on = 1;
        ::setsockopt(tester_fd, IPPROTO_TCP, TCP_REPAIR, &repair_on, sizeof(repair_on));
        ::close(tester_fd);
    };

    if (tester_fd < 0) return {};

    TesterAutoAckDrop ack_drop(cfg);
    dut.tcpControl()->closeTcp(dut_socket);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    const auto seq = queryTcpSeqRange(tester_fd);
    if (!seq.has_value()) {
        ::close(tester_fd);
        return {};
    }

    // Step 3 — tester FIN+ACK that does NOT acknowledge the DUT FIN, so the DUT
    // in FIN-WAIT-1 crosses into CLOSING (RFC 793 §3.9).
    {
        ::tc8::stimulus::TcpSegmentSpec fin_seg{};
        fin_seg.src_port = remote_port;
        fin_seg.dst_port = local_port;
        fin_seg.seq_num  = seq->snd_nxt;
        fin_seg.ack_num  = seq->rcv_nxt - 1U;
        fin_seg.flags    = ::tc8::stimulus::kTcpFlagFin | ::tc8::stimulus::kTcpFlagAck;
        emitTcpFrame(cfg, iface, cfg.dut.mac, fin_seg,
                     /*initial_wait=*/std::chrono::milliseconds(0));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Step 4 — tester ACK that DOES acknowledge the DUT FIN, driving
    // CLOSING -> TIME-WAIT silently.
    {
        ::tc8::stimulus::TcpSegmentSpec ack_seg{};
        ack_seg.src_port = remote_port;
        ack_seg.dst_port = local_port;
        ack_seg.seq_num  = seq->snd_nxt + 1U;
        ack_seg.ack_num  = seq->rcv_nxt;
        ack_seg.flags    = ::tc8::stimulus::kTcpFlagAck;
        emitTcpFrame(cfg, iface, cfg.dut.mac, ack_seg,
                     /*initial_wait=*/std::chrono::milliseconds(0));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    silent_close();

    TcpTimeWaitInfo info{};
    info.ok                  = true;
    info.tester_seq_post_fin = seq->snd_nxt + 1U;
    info.tester_ack_post_fin = seq->rcv_nxt;
    return info;
}

}  // namespace tc8::sce::tcp
