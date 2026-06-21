#pragma once

#include <cstdint>

struct netif;

namespace tc8::lwip_dut {

// Set the active ingress prohibited-emission flavor (the kIngressFault* /
// kArpFault{Reply,Learn}* catalog in tc8/upper_tester_protocol.h). Thread-safe —
// written from the OpSetIngressFlavor UT handler on the upper-tester thread, read on
// the tapif rx thread by the input hook. kIngressFaultNone (the default) disables it.
void setIngressFaultFlavor(std::uint8_t flavor);

// Install the §4.2.4.2 ARP ingress fault hook on the netif: wraps netif->input so
// that, while an ingress flavor is active, the reception cases' forbidden behaviour
// is produced as the inbound malformed/foreign ARP frame arrives — the conformant
// DUT drops it and emits nothing, so there is no egress to corrupt.
// kArpFaultReplyToDropFrame synthesizes the prohibited ARP Reply (sent via
// netif->linkoutput, which the egress hook leaves untouched while no egress flavor
// is armed); kArpFaultLearnFromDropFrame forces the dropped Response's
// (sender_ip -> sender_hw) into the ARP table as a static entry. The original frame
// is always forwarded to lwIP afterwards (which drops it as normal); lwIP is
// untouched. Idempotent; call after the netif is up.
void installArpIngressFaultHook(struct netif *nif);

}  // namespace tc8::lwip_dut
