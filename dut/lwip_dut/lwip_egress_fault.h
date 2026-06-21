#pragma once

#include <cstdint>

struct netif;

namespace tc8::lwip_dut {

// Set the active egress field-fault flavor (the k*Fault* egress catalog in
// tc8/upper_tester_protocol.h). Thread-safe — written from the OpSetEgressFlavor UT
// handler on the upper-tester thread, read on the tcpip thread by the link-output
// hook. kEgressFaultNone (the default) disables the mutation entirely.
void setEgressFaultFlavor(std::uint8_t flavor);

// Install the egress field-fault hook on the netif: wraps netif->linkoutput so
// that, while a non-None flavor is active, the DUT-emitted frame has the matching
// header field corrupted (and the affected checksum recomputed) before it leaves on
// the tap. lwIP itself is untouched — the fault lives in the fixture's own
// link-output glue, the lwIP analog of a tc8-dut emit-flavor. Generic over protocol
// (the §4.2 ARP fields today; IPv4/UDP/TCP/ICMP join the same hook). Idempotent;
// call once after the netif is up.
void installEgressFaultHook(struct netif *nif);

}  // namespace tc8::lwip_dut
