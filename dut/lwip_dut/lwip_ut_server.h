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
// OpOpenTcpSocket..OpReceiveTcpDataOob (0x03..0x0B) and OpPing (0x15).
// Everything else answers kStatusUnknownOpcode — visible, never silent.
//
// Call once after the stack is up; aborts the process on socket/bind
// failure because a half-up DUT (stack answering, UT dead) is exactly
// the state the topology preflight cannot distinguish from "UT not
// implemented".
void StartUpperTesterServer(std::uint32_t dut_ip_be);

}  // namespace tc8::lwip_dut
