#pragma once

#include "tc8/net/socket_backend.h"
#include "upper_tester/ut_server.h"

namespace tc8::lwip_dut {

// The lwIP DUT's Upper Tester opcode extension: OpConditionArpCache (0x17), whose
// aging actions the Linux reference DUT deliberately does NOT carry (its §4.2.4.2 cache
// conditioning rides the smoke-test.sh netns sysctls, while lwIP's compile-time
// ARP_MAXAGE is reachable only from inside the stack). Registered on the
// platform-agnostic UT core (UpperTesterServer::registerOpcode) rather than built
// into it — keeping the lwIP etharp aging machinery out of the cross-platform
// core, the lwIP analog of PosixUtExtensions::registerOn. The handler holds no
// state of its own (it drives netif_default's ARP table directly, and reaches the
// static-entry calls through the injected backend below), so this is a free
// function, not a stateful extensions object. Call before server.start().
//
// `neighbors` carries the TC8 §4.2.3 static-entry actions of the same opcode
// (ut::applyArpStaticEntry) — the stack's own net::SocketBackend, injected rather
// than constructed here so the handler uses exactly the backend the fixture owns.
// It must outlive the server.
void registerLwipUtExtensions(tc8::ut::UpperTesterServer &server,
                              tc8::net::SocketBackend &neighbors);

}  // namespace tc8::lwip_dut
