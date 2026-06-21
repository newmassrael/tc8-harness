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

// Install the ARP ingress fault hook on the netif: wraps netif->input so that,
// while an ingress prohibited-emission flavor (kArpFaultReplyToDropFrame, ...) is
// active, the §4.2.4.2 reception cases' forbidden emission is produced as the
// inbound malformed/foreign ARP frame arrives — the conformant DUT drops it and
// emits nothing, so there is no egress to corrupt. kArpFaultReplyToDropFrame
// synthesizes the prohibited ARP Reply and sends it back via the saved
// link-output. The original frame is always forwarded to lwIP afterwards (which
// drops it as normal); lwIP is untouched. Idempotent; call after the egress hook
// (it reuses the same saved link-output) and after the netif is up.
void installArpFaultIngressHook(struct netif *nif);

}  // namespace tc8::lwip_dut
