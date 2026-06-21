#pragma once

#include <cstdint>

struct netif;

namespace tc8::lwip_dut {

// Set the active ingress-reaction flavor (the kIngressFault* catalog in
// tc8/upper_tester_protocol.h: kArpFault{Reply,Learn}* and kUdpFaultAcceptBadChecksum).
// Thread-safe — written from the OpSetIngressFlavor UT handler on the upper-tester
// thread, read on the tapif rx thread by the input hook. kIngressFaultNone (the
// default) disables it.
void setIngressFaultFlavor(std::uint8_t flavor);

// Install the ingress reaction-fault hook on the netif: wraps netif->input so that,
// while an ingress flavor is active, the reception cases' forbidden reaction is
// produced as the inbound frame arrives — the property the positive case proves
// absent. Three reaction kinds:
//   * §4.2.4.2 ARP prohibited emission — a conformant DUT drops the malformed/foreign
//     ARP frame and emits nothing, so there is no egress to corrupt.
//     kArpFaultReplyToDropFrame synthesizes the prohibited ARP Reply (sent via
//     netif->linkoutput, which the egress hook leaves untouched while no egress
//     flavor is armed); kArpFaultLearnFromDropFrame forces the dropped Response's
//     (sender_ip -> sender_hw) into the ARP table as a static entry.
//   * §4.6.5.4 UDP prohibited acceptance — a conformant DUT discards the malformed
//     datagram. kUdpFaultAcceptBadChecksum zeroes the inbound UDP checksum field so
//     lwIP's checksum-validation gate skips and delivers it to the receive-counting
//     app (the only drop gate for FIELDS_09/10/15 + DATAGRAMLENGTH_01 on lwIP).
//   * §4.6.5.4 UDP prohibited rejection — a conformant DUT accepts a valid edge-case
//     datagram. kUdpFaultRejectValid swallows the inbound data-listener frame (never
//     forwards it to lwIP) so the receive-counting app never sees one it must accept
//     (FIELDS_03 src port 0 / _16 checksum 0).
// Every other inbound frame (and the ARP/accept faults' frames) is forwarded to lwIP
// afterwards; only kUdpFaultRejectValid drops one. lwIP itself is untouched.
// Idempotent; call after the netif is up.
void installIngressFaultHook(struct netif *nif);

}  // namespace tc8::lwip_dut
