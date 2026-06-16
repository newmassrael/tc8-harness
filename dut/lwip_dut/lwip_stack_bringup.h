#pragma once

#include "lwip/ip4_addr.h"

namespace tc8::lwip_dut {

// Shared lwIP unix-port stack bring-up for the fixture binaries in this
// directory (the conformance DUT tc8-lwip-dut and the standalone UTM
// tc8-lwip-utm). Factored out so the stack-init sequence — and the
// LWIP_PLATFORM_ASSERT sink it implies — has a single home rather than a
// copy per binary.

// Bring up the threaded lwIP stack on the preconfigured tap netif
// (PRECONFIGURED_TAPIF env, consumed by the unix-port tapif driver), assign a
// static address from the environment, and seed the RFC 6528 ISN secret before
// the first TCP pcb is created (LWIP_HOOK_TCP_ISN fires on every connect/listen
// ISS pick). Returns the assigned address. Exits the process on any failure.
// Call once, on the main thread, before starting any server.
//
//   TC8_LWIP_DUT_IP    (default 172.16.0.2)
//   TC8_LWIP_DUT_MASK  (default 255.255.255.0)
//   TC8_LWIP_DUT_GW    (default 172.16.0.1)
ip4_addr_t BringUpLwipStack();

// Install a SIGTERM handler (sigaction, no SA_RESTART, so pause() returns with
// EINTR) and park the calling main thread until it fires, then return so the
// caller runs its own teardown on the main thread — never in signal context.
void ParkUntilSigterm();

}  // namespace tc8::lwip_dut
