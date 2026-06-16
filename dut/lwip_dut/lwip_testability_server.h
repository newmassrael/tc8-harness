#pragma once

#include <cstdint>

#include "tc8/testability_protocol.h"

namespace tc8::lwip_dut {

// AUTOSAR Testability Protocol endpoint (PRS_TPSP §6, AUTOSAR TC 1.2.0) for
// the lwIP DUT fixture — the functional mirror of
// dut/dut_service/testability_server.{h,cpp}, rebuilt on the lwIP socket API,
// exactly as lwip_ut_server.cpp mirrors the opcode UpperTesterServer. The wire
// framing + codec are the shared SSOT in include/tc8/testability_protocol.h,
// so a tester decodes a lwIP-fixture endpoint and a Linux tc8-dut endpoint
// identically; only the syscall layer differs.
//
// Served standard groups (PRS_TPSP §6.10):
//   * GENERAL (0x00): GET_VERSION, START_TEST, END_TEST.
//   * UDP (0x01): CREATE_AND_BIND, SEND_DATA, CLOSE_SOCKET, SHUTDOWN,
//     RECEIVE_AND_FORWARD, CONFIGURE_SOCKET.
//   * TCP (0x02): CREATE_AND_BIND, CONNECT, LISTEN_AND_ACCEPT, SEND_DATA,
//     CLOSE_SOCKET, SHUTDOWN, RECEIVE_AND_FORWARD, CONFIGURE_SOCKET.
//   * ICMP (0x03): ECHO_REQUEST.
//
// Structural deviations from the Linux server, each forced by a stack
// property (full rationale at the call sites in the .cpp):
//   * The CLOSE_SOCKET abort uses tcp_abort() on the raw pcb (reached through
//     the lwip/priv/sockets_priv.h fd->pcb bridge) instead of SO_LINGER{on,0}
//     + close: lwIP only aborts a lingering close when unsent data remains, so
//     an empty queue always FINs. The netlink SOCK_DESTROY TIME-WAIT-residual
//     path has no lwIP analog and is dropped — tcp_abort RSTs straight to
//     CLOSED, leaving no residual to destroy.
//   * ECHO_REQUEST emits through a raw pcb (IP_PROTO_ICMP) under the core lock;
//     lwIP's socket layer exposes no unprivileged ICMP datagram socket. The
//     Echo Request body is built by the shared tc8::wire builder, unchanged.
//   * CONFIGURE_SOCKET maps TTL/TOS/Nagle to lwip_setsockopt; the DF, IP
//     timestamp-option and MSS parameters have no lwIP socket option and
//     answer E_NOK (the matching platform_known_fail, surfaced — never silent).
//   * Response and asynchronous Event egress on the shared listener socket are
//     serialised by a send mutex: lwIP gives no cross-thread send ordering
//     guarantee on one netconn, unlike the Linux kernel the original relies on.
//
// The OEM extension/override seam (registerPrimitive) is intentionally not
// mirrored here: the fixture is a conformance DUT serving the standard groups,
// and a fixture-local seam with no caller would be dead code. OEM extension
// stays the Linux server / standalone tc8-utm's concern.

// Bind the testability UDP listener (default PRS_TPSP port 30700) and start the
// server thread. Additive, like the Linux tc8-dut: a bind failure is logged and
// the fixture keeps serving the opcode UT. Safe to call once after the stack is
// up. No-op if already started.
void StartTestabilityServer(std::uint16_t port = tc8::testability::kDefaultPort);

// SIGTERM teardown: signal the server + async-event worker threads to exit,
// join them, and close every testability socket (an abort-close RSTs, mirroring
// the kernel closing sockets on Linux process death). Called from the main
// thread. No-op before StartTestabilityServer.
void StopTestabilityServer();

}  // namespace tc8::lwip_dut
