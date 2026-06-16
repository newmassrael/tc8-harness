#pragma once

#include "upper_tester/ut_server.h"

namespace tc8::lwip_dut {

// The lwIP DUT's Upper Tester opcode extension: OpConditionArpCache (0x17), which
// the Linux reference DUT deliberately does NOT carry (its §4.2.4.2 cache
// conditioning rides the smoke-test.sh netns sysctls, while lwIP's compile-time
// ARP_MAXAGE is reachable only from inside the stack). Registered on the
// platform-agnostic UT core (UpperTesterServer::registerOpcode) rather than built
// into it — keeping the lwIP etharp aging machinery out of the cross-platform
// core, the lwIP analog of PosixUtExtensions::registerOn. The handler is
// stateless (it drives netif_default's ARP table directly), so this is a free
// function, not a stateful extensions object. Call before server.start().
void registerLwipUtExtensions(tc8::ut::UpperTesterServer &server);

}  // namespace tc8::lwip_dut
