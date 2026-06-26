#pragma once

#include "lwip/ip4_addr.h"

struct netif;  // lwIP global type, forwarded for the callback signature below

namespace tc8::lwip_dut {

// Shared lwIP unix-port stack bring-up for the binaries in this directory (the
// conformance DUT tc8-lwip-dut and the standalone UTM tc8-lwip-utm), and the
// reference bring-up shipped in utm-sdk-lwip. Factored out so the stack-init
// sequence has a single home rather than a copy per binary. It is fixture-free:
// fault hooks come via the afterNetifUp callback, and the LWIP_PLATFORM_ASSERT
// sink stays in the DUT.

// Optional hook invoked under the TCPIP core lock, immediately after the default
// netif is up — the atomic point at which a fixture installs link-layer hooks
// (the conformance DUT wraps the netif's input/output for fault injection here),
// before the stack can process a single frame. The UTM passes nothing, so its
// bring-up pulls in no fixture code: the dependency is an opaque function pointer.
using PostNetifUpFn = void (*)(struct netif *nif);

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
ip4_addr_t BringUpLwipStack(PostNetifUpFn afterNetifUp = nullptr);

// Install a SIGTERM handler (sigaction, no SA_RESTART, so pause() returns with
// EINTR) and park the calling main thread until it fires, then return so the
// caller runs its own teardown on the main thread — never in signal context.
void ParkUntilSigterm();

}  // namespace tc8::lwip_dut
