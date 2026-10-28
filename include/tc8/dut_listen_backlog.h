#pragma once

// The listen backlog the harness asks a DUT for when a case opens a passive socket.
// The tester side (the Testability adapter) and the DUT side (the opcode Upper Tester
// server) both pass it, so the two backends cannot offer a case different listeners.
//
// Most cases need ONE connection per listener, but a backlog is a ceiling rather than a
// requirement, and some cases deliberately offer several at once: TCP_CONNECTION_ESTAB_01
// sends three SYNs from three source ports to a single listener and expects a SYN+ACK for
// each.
//
// MEASURED: a backlog of 1 passed on the Linux DUT, whose accept queue is lenient about the
// value, and silently lost legs 2 and 3 on the lwIP fixture, which enforces it exactly
// (tcp_listen_with_backlog, counting half-open connections). The case then reported
// `no_dut_synack_for_leg2`, a DUT-shaped reason for a listener the harness itself had
// under-provisioned. The opcode server was corrected to 8; the Testability adapter kept 1
// under a comment that called it parity, and failed TCP_CONNECTION_ESTAB_01 and
// TCP_FLAGS_PROCESSING_05 on the lwIP fixture until it shared this constant.
//
// 8 covers the widest simultaneous offer in the suite (3) with headroom; no case asserts a
// backlog refusal.

namespace tc8 {

inline constexpr int kDutPassiveListenBacklog = 8;

}  // namespace tc8
