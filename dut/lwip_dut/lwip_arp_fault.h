#pragma once

#include <cstdint>

struct netif;

namespace tc8::lwip_dut {

// Set the active §4.2 ARP egress fault flavor (the kArpFault* bytes in
// tc8/upper_tester_protocol.h). Thread-safe — called from the OpSetArpFlavor UT
// handler on the upper-tester thread, read on the tcpip thread by the egress hook.
// kArpFaultNone (the default) disables the mutation entirely.
void setArpFaultFlavor(std::uint8_t flavor);

// Install the ARP egress fault hook on the netif: wraps netif->linkoutput so that,
// while a non-None flavor is active, the DUT-emitted ARP frame (request or reply)
// has the matching header field corrupted before it leaves on the tap. lwIP itself
// is untouched — the fault lives in the fixture's own link-output glue, the lwIP
// analog of a tc8-dut emit-flavor. Idempotent; call once after the netif is up.
void installArpFaultEgressHook(struct netif *nif);

}  // namespace tc8::lwip_dut
