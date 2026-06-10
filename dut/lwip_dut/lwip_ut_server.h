#pragma once

#include <cstdint>

namespace tc8::lwip_dut {

// Starts the Upper Tester UDP server (tc8::ut::kPort) on a dedicated
// application thread driving the lwIP socket API. `dut_ip_be` is the
// fixture's static interface address in network byte order — active
// TCP opens bind their local endpoint to it so the tester can filter
// DUT-originated segments deterministically (mirrors the Linux
// tc8-dut's iface_ip bind).
//
// Implemented opcode surface (see include/tc8/upper_tester_protocol.h):
// OpGetReceivedUdp/OpTriggerSendUdp (0x01/0x02),
// OpOpenTcpSocket..OpReceiveTcpDataOob (0x03..0x0B),
// OpQueryTcpInfo (0x13), OpCreateUdpReceivePorts (0x14) and OpPing
// (0x15). Everything else answers kStatusUnknownOpcode — visible,
// never silent.
//
// Call once after the stack is up; aborts the process on socket/bind
// failure because a half-up DUT (stack answering, UT dead) is exactly
// the state the topology preflight cannot distinguish from "UT not
// implemented".
void StartUpperTesterServer(std::uint32_t dut_ip_be);

// SIGTERM teardown path: abort (RST) every open UT TCP slot so the
// tester-side halves of case-leaked connections reach CLOSED instead
// of orphaning in FIN-WAIT-2 — a userspace stack emits nothing on
// SIGKILL, unlike the Linux DUT whose kernel closes sockets on process
// death, and a FIN-WAIT-2 orphan swallows the next case's SYN when the
// respawned stack reuses the same deterministic port quad. Called from
// the main thread (never a signal handler — it takes the tcpip core
// lock). No-op before StartUpperTesterServer.
void AbortUpperTesterSlots();

}  // namespace tc8::lwip_dut
