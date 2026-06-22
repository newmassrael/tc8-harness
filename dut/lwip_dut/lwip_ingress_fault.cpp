// Ingress reaction-fault seam for the lwIP fixture — the netif input wrapper the
// reception `_NEG` cases drive via UT 0x19 OpSetIngressFlavor. The conformant DUT's
// reaction to an inbound frame is the property under test (it drops the frame), so
// there is no DUT egress field to corrupt; the wrapper makes the buggy DUT exhibit
// the forbidden reaction as the frame arrives:
//   * §4.2.4.2 ARP prohibited emission — synthesize the prohibited ARP Reply
//     (ARP_21/27/37/42), or wrongly learn the dropped Response's address
//     (ARP_22/28/38).
//   * §4.3 ICMPv4 prohibited emission — synthesize the prohibited ICMP reply a
//     conformant DUT must NOT send (Information Reply for an Info Request /
//     TYPE_16; Echo Reply for a bad-checksum Echo / TYPE_10 or an unknown type /
//     ERROR_05; Parameter Problem for a fragmented / ERROR_03 or broadcast /
//     ERROR_04 trigger), addressed back to the trigger's sender.
//   * §4.8 TCP behavioral prohibited emission — synthesize the prohibited TCP
//     response on the connection's 4-tuple (a RST after a pure ACK in ESTABLISHED /
//     ACKNOWLEDGEMENT_04 + dup-ACK FLAGS_PROCESSING_11, a challenge ACK to a malformed /
//     multicast segment the DUT must drop / HEADER_07/08/09/11, or a RST in response to a
//     disruptive segment the DUT must answer with silence — the §4.8 must-not-respond family
//     spanning SYN-SENT / EST / the close-states, FLAGS_INVALID_03/04/15, FLAGS_PROCESSING_07/08,
//     CLOSING_07/08/09), swapped from the inbound trigger.
//   * §4.6.5.4 UDP prohibited acceptance — zero the inbound datagram's UDP checksum
//     so lwIP's validation gate skips and delivers it to the receive-counting app
//     (UDP_FIELDS_09/10/15).
// lwIP itself is untouched — fixture glue only.
#include "lwip_ingress_fault.h"

#include <atomic>
#include <cstdint>
#include <cstring>

#include "lwip/err.h"
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/tcpip.h"

#include "tc8/upper_tester_protocol.h"
#include "wire/ip_checksum.h"

#include "lwip_wire.h"

namespace tc8::lwip_dut {
namespace {

namespace ut = ::tc8::ut;

// The active ingress flavor: written on the UT thread (OpSetIngressFlavor handler),
// read on the tapif rx thread (the input hook). Relaxed ordering is sufficient.
std::atomic<std::uint8_t> g_ingress_flavor{ut::kIngressFaultNone};

// The netif's original input (tcpip_input), saved at install. Every inbound frame
// is forwarded to it after (optionally) producing the prohibited emission, so
// lwIP's own reception (which drops the malformed/foreign frame) is unchanged.
netif_input_fn g_orig_input = nullptr;

// kArpFaultReplyToDropFrame: a buggy DUT answering an ARP frame it should have
// dropped (§4.2.4.2 ARP_21/27/37/42 reply-absence). `rx` points at the inbound
// Ethernet+ARP frame; the synthesized Reply is addressed back to its sender with
// the DUT's own identity, so the case guard's `opcode == 2 and sender_hw ==
// dut_iface_mac` fires. Sent via nif->linkoutput — while no egress flavor is armed,
// the egress hook leaves it untouched and forwards it to the raw tap. No core lock
// needed: the tap link-output is a stack-buffered write(2), and pbuf_alloc on this
// (rx) thread is what low_level_input already does for every inbound frame.
void emitProhibitedArpReply(struct netif *nif, const std::uint8_t *rx) {
    struct pbuf *p = pbuf_alloc(PBUF_RAW, kArpFrameLen, PBUF_RAM);
    if (p == nullptr) {
        return;
    }
    auto *o = static_cast<std::uint8_t *>(p->payload);
    std::memcpy(o + 0, rx + kArpSenderHw, 6);             // eth dst = requester sender_hw
    std::memcpy(o + 6, nif->hwaddr, 6);                   // eth src = DUT MAC
    put16(o, kEthTypeOff, 0x0806);
    put16(o, kArpHType, 0x0001);
    put16(o, kArpPType, 0x0800);
    o[kArpHLen] = 6;
    o[kArpPLen] = 4;
    put16(o, kArpOpcode, 0x0002);                         // Reply
    std::memcpy(o + kArpSenderHw, nif->hwaddr, 6);        // sender_hw = DUT MAC
    const std::uint32_t dut_ip = ip4_addr_get_u32(netif_ip4_addr(nif));
    std::memcpy(o + kArpSenderIp, &dut_ip, 4);            // sender_ip = DUT IP (network order)
    std::memcpy(o + kArpTargetHw, rx + kArpSenderHw, 6);  // target_hw = requester sender_hw
    std::memcpy(o + kArpTargetIp, rx + kArpSenderIp, 4);  // target_ip = requester sender_ip
    nif->linkoutput(nif, p);
    pbuf_free(p);
}

// kIcmpFaultSynth*: a buggy DUT answering an inbound ICMP trigger the conformant DUT
// stays silent for (§4.3 ICMPv4 prohibited emission — Info Request → must not Info
// Reply / TYPE_16; bad-checksum or unknown-type ICMP → must not reply at all /
// TYPE_10, ERROR_05; broadcast or fragmented options trigger → must not Parameter
// Problem / ERROR_03, ERROR_04). `rx` points at the inbound Ethernet+IPv4+ICMP frame;
// the synthesized reply carries the DUT's source identity (eth + IPv4 src) addressed
// back to the trigger's sender, so the case guard's `src_ip == dut_iface_ip` fires and
// the dispatch's type narrowing selects the reply. `reply_type` is the ICMP type the
// flavor names (Echo Reply 0 / Parameter Problem 12 / Information Reply 16). The
// 8-byte ICMP body (type, code 0, checksum, zeroed rest-of-header) is the minimum a
// well-formed reply needs — the guards read only type + src_ip, never the body. Both
// checksums are computed with the shared tc8::wire `inetChecksum` SSOT, so the frame
// is valid at every layer, not merely dissectable.
// Sent via nif->linkoutput like the ARP synthesis — no egress flavor armed, so the
// egress hook forwards it untouched. Reads only the inbound IPv4 fixed header
// (proto + source), which is present whatever the trigger's IHL or fragment offset.
void emitProhibitedIcmpReply(struct netif *nif, const std::uint8_t *rx,
                             std::uint8_t reply_type) {
    constexpr std::uint16_t kL4Off    = kEthHdrLen + kIpHdrLenMin;        // 34
    constexpr std::uint16_t kFrameLen = kL4Off + kIcmpMinHdrLen;          // 42
    struct pbuf *p = pbuf_alloc(PBUF_RAW, kFrameLen, PBUF_RAM);
    if (p == nullptr) {
        return;
    }
    auto *o = static_cast<std::uint8_t *>(p->payload);
    std::memset(o, 0, kFrameLen);
    std::memcpy(o + 0, rx + 6, 6);                        // eth dst = trigger's eth src (the tester)
    std::memcpy(o + 6, nif->hwaddr, 6);                   // eth src = DUT MAC
    put16(o, kEthTypeOff, 0x0800);                        // IPv4
    o[kIpVerIhlOff] = 0x45;                               // version 4, IHL 5 (no options)
    put16(o, kIpTotalLenOff, kIpHdrLenMin + kIcmpMinHdrLen);  // 28
    o[kIpTtlOff]   = 64;
    o[kIpProtoOff] = kIpProtoIcmp;
    const std::uint32_t dut_ip = ip4_addr_get_u32(netif_ip4_addr(nif));
    std::memcpy(o + kIpSrcOff, &dut_ip, 4);               // src = DUT IP (network order)
    std::memcpy(o + kIpDstOff, rx + kIpSrcOff, 4);        // dst = trigger's IPv4 src (the tester)
    put16(o, kIpHdrChecksumOff, ::tc8::wire::inetChecksum(o + kEthHdrLen, kIpHdrLenMin));
    o[kL4Off + kIcmpTypeOff] = reply_type;               // code + rest-of-header stay 0 from memset
    put16(o, kL4Off + kIcmpChecksumOff, ::tc8::wire::inetChecksum(o + kL4Off, kIcmpMinHdrLen));
    nif->linkoutput(nif, p);
    pbuf_free(p);
}

// kTcpSynth*: a buggy DUT emitting a forbidden TCP response to a segment it must silently
// accept or drop — a RST on a pure ACK in ESTABLISHED (kTcpSynthRst, §4.8.6.18
// ACKNOWLEDGEMENT_04 + §4.8.6.7 FLAGS_PROCESSING_11), a challenge ACK on a malformed/multicast
// segment (kTcpSynthAck, §4.8.6.16 HEADER_07/08/09/11), or a RST on a disruptive segment the
// DUT must answer with silence (kTcpSynthRstOnDisruptive, the §4.8 must-not-respond family —
// FLAGS_INVALID_03/04/15, FLAGS_PROCESSING_07/08, CLOSING_07/08/09).
// `rx` points at the inbound trigger; the synthesized segment
// carries `tcp_flags` on the connection's 4-tuple, derived by swapping the trigger's source
// for the destination — except the source IP, which is the DUT's own netif address so a
// multicast-destination trigger (HEADER_11) still yields a DUT-sourced reply. The case guards
// (is_dut_rst / is_pure_dut_ack) check only that 4-tuple + the flag, never seq/ack, so those
// stay 0 (a real segment's seq is connection-state-derived, which this stateless hook does not
// track). Both checksums use the shared tc8::wire SSOT (IPv4 header via inetChecksum, TCP via
// tcpChecksum's pseudo-header fold) so the frame is valid at every layer. Sent via
// nif->linkoutput like the ARP/ICMP synthesis.
void emitProhibitedTcpSegment(struct netif *nif, const std::uint8_t *rx, std::uint8_t tcp_flags) {
    constexpr std::uint16_t kL4Off    = kEthHdrLen + kIpHdrLenMin;        // 34
    constexpr std::uint16_t kFrameLen = kL4Off + kTcpMinHdrLen;          // 54
    struct pbuf *p = pbuf_alloc(PBUF_RAW, kFrameLen, PBUF_RAM);
    if (p == nullptr) {
        return;
    }
    auto *o = static_cast<std::uint8_t *>(p->payload);
    std::memset(o, 0, kFrameLen);
    std::memcpy(o + 0, rx + 6, 6);                        // eth dst = trigger's eth src (the tester)
    std::memcpy(o + 6, nif->hwaddr, 6);                   // eth src = DUT MAC
    put16(o, kEthTypeOff, 0x0800);                        // IPv4
    o[kIpVerIhlOff] = 0x45;                               // version 4, IHL 5
    put16(o, kIpTotalLenOff, kIpHdrLenMin + kTcpMinHdrLen);  // 40
    o[kIpTtlOff]   = 64;
    o[kIpProtoOff] = kIpProtoTcp;
    const std::uint32_t dut_ip = ip4_addr_get_u32(netif_ip4_addr(nif));
    std::memcpy(o + kIpSrcOff, &dut_ip, 4);               // src = DUT IP (own netif addr; trigger dst may be multicast)
    std::memcpy(o + kIpDstOff, rx + kIpSrcOff, 4);        // dst = trigger's IPv4 src = tester IP
    put16(o, kIpHdrChecksumOff, ::tc8::wire::inetChecksum(o + kEthHdrLen, kIpHdrLenMin));
    std::uint32_t tester_ip = 0;
    std::memcpy(&tester_ip, rx + kIpSrcOff, 4);           // trigger's IPv4 src (NBO) for the pseudo-header
    const std::uint16_t rx_l4 = l4RegionOffset(rx);
    put16(o, kL4Off + kTcpSrcPortOff, get16(rx, rx_l4 + kTcpDstPortOff));  // src port = DUT local port
    put16(o, kL4Off + kTcpDstPortOff, get16(rx, rx_l4 + kTcpSrcPortOff));  // dst port = tester remote port
    o[kL4Off + kTcpDataOffOff] = 0x50;                    // data offset 5 (20 B header, no options)
    o[kL4Off + kTcpFlagsOff]   = tcp_flags;               // RST or ACK
    put16(o, kL4Off + kTcpChecksumOff,
          ::tc8::wire::tcpChecksum(dut_ip, tester_ip, o + kL4Off, kTcpMinHdrLen));
    nif->linkoutput(nif, p);
    pbuf_free(p);
}

// kArpFaultLearnFromDropFrame: a buggy DUT that wrongly accepted a malformed/foreign
// ARP Response it should have dropped (§4.2.4.2 ARP_22/28/38 drop-and-emit). `rx`
// points at the inbound frame; its (sender_ip -> sender_hw) is forced into the ARP
// table as a static entry, so the DUT's subsequent UT-provoked UDP egress resolves
// straight to the dropped frame's MAC instead of emitting its own ARP Request — the
// exact violation the positive guard forbids. Under the core lock: this rx thread is
// not the tcpip thread, so it must hold it to touch the ARP table.
void learnDropFrameAddress(const std::uint8_t *rx) {
    ip4_addr_t ip;
    std::memcpy(&ip.addr, rx + kArpSenderIp, 4);  // network order, as ip4_addr_t stores it
    struct eth_addr mac;
    std::memcpy(mac.addr, rx + kArpSenderHw, 6);
    LOCK_TCPIP_CORE();
    etharp_add_static_entry(&ip, &mac);
    UNLOCK_TCPIP_CORE();
}

// The two UDP ingress reaction faults both target the data-listener datagram
// (dst port kDataPort), so the UT control channel (kPort) is never disturbed:
//   * kUdpFaultAcceptBadChecksum (§4.6.5.4 FIELDS_09/10/15 + DATAGRAMLENGTH_01):
//     zero the inbound UDP checksum so lwIP's `udphdr->chksum != 0` guard skips
//     validation and delivers a datagram it must drop. This is the only drop gate
//     for these cases on lwIP — lwIP ignores the UDP length field for plain UDP, so
//     the length mutants fail only because the length field is checksum-covered, and
//     FIELDS_15 corrupts the checksum directly. The UDP checksum is not part of the
//     IPv4 header checksum, so zeroing it leaves the IPv4 header valid.
//   * kUdpFaultRejectValid (§4.6.5.4 FIELDS_03 src port 0 / _16 checksum 0): swallow
//     the (valid) datagram — never forward it to lwIP — so the receive-counting app
//     never sees one the DUT must accept.
err_t ingressFaultInput(struct pbuf *p, struct netif *nif) {
    const std::uint8_t flavor = g_ingress_flavor.load(std::memory_order_relaxed);
    if (flavor != ut::kIngressFaultNone && p != nullptr && p->payload != nullptr) {
        auto *f = static_cast<std::uint8_t *>(p->payload);
        if (p->len >= kArpFrameLen && isArp(f)) {
            if (flavor == ut::kArpFaultReplyToDropFrame) {
                emitProhibitedArpReply(nif, f);
            } else if (flavor == ut::kArpFaultLearnFromDropFrame &&
                       get16(f, kArpOpcode) == 0x0002) {  // learn only from a Response
                learnDropFrameAddress(f);
            }
        } else if ((flavor == ut::kUdpFaultAcceptBadChecksum ||
                    flavor == ut::kUdpFaultRejectValid) &&
                   p->len >= kIpProtoOff + 1 && isIpv4(f) &&
                   f[kIpProtoOff] == kIpProtoUdp &&
                   p->len >= l4RegionOffset(f) + kUdpHdrLen) {
            const std::uint16_t udp = l4RegionOffset(f);
            if (get16(f, udp + kUdpDstPort) == ut::kDataPort) {
                if (flavor == ut::kUdpFaultRejectValid) {
                    pbuf_free(p);     // swallow — the DUT wrongly drops a frame it must accept
                    return ERR_OK;
                }
                put16(f, udp + kUdpChecksum, 0x0000);  // accept-bad-checksum: skip lwIP's gate
            }
        } else if ((flavor == ut::kIcmpFaultSynthEchoReply ||
                    flavor == ut::kIcmpFaultSynthInfoReply ||
                    flavor == ut::kIcmpFaultSynthParamProblem) &&
                   p->len >= kEthHdrLen + kIpHdrLenMin && isIpv4(f) &&
                   f[kIpProtoOff] == kIpProtoIcmp) {
            // §4.3 prohibited emission: the conformant DUT drops the trigger and stays
            // silent, so the input hook synthesizes the forbidden ICMP reply. The flavor
            // names the reply type; the original frame still goes to lwIP, which drops it.
            const std::uint8_t reply_type =
                flavor == ut::kIcmpFaultSynthInfoReply    ? kIcmpTypeInfoReply :
                flavor == ut::kIcmpFaultSynthParamProblem ? kIcmpTypeParamProblem :
                                                            kIcmpTypeEchoReply;
            emitProhibitedIcmpReply(nif, f, reply_type);
        } else if ((flavor == ut::kTcpSynthRst || flavor == ut::kTcpSynthAck ||
                    flavor == ut::kTcpSynthRstOnDisruptive) &&
                   p->len >= kEthHdrLen + kIpHdrLenMin && isIpv4(f) &&
                   f[kIpProtoOff] == kIpProtoTcp &&
                   p->len >= l4RegionOffset(f) + kTcpMinHdrLen) {
            const std::uint16_t tcp = l4RegionOffset(f);
            const std::uint8_t flags = f[tcp + kTcpFlagsOff];
            if (flavor == ut::kTcpSynthRst) {
                // §4.8.6.18 ACKNOWLEDGEMENT_04 + §4.8.6.7 FLAGS_PROCESSING_11 (a duplicate ACK
                // in ESTABLISHED, itself a pure ACK): the conformant DUT silently accepts the
                // pure ACK, so the hook synthesizes the prohibited RST. The gate is
                // a pure ACK (ACK set; SYN/FIN/RST clear; no payload) — the handshake SYN,ACK
                // carries SYN, the DUT's own segments are egress (not seen here). The gate is
                // level-triggered, not one-shot: every matching pure ACK synthesizes a RST
                // (the post-close FIN's ACK also matches), but the surplus RSTs carry seq=0,
                // are out-of-window, and are inert to the guard (which needs one observation).
                // Per-phase arming scopes the first synthesis past the handshake.
                const bool pure_ack =
                    (flags & kTcpFlagAck) != 0U &&
                    (flags & (kTcpFlagSyn | kTcpFlagFin | kTcpFlagRst)) == 0U &&
                    !tcpHasPayload(f, tcp);
                if (pure_ack) {
                    emitProhibitedTcpSegment(nif, f, kTcpFlagRst);
                }
            } else if (flavor == ut::kTcpSynthAck) {
                // §4.8.6.16 HEADER_07/08/09/11: the conformant DUT silently drops a malformed
                // (bad data offset / zero checksum) or multicast-addressed segment, so the
                // hook synthesizes the prohibited challenge ACK. The gate is SYN or PSH — the
                // malformed triggers carry PSH (data segments) or SYN (multicast SYN), while
                // the tester's pure-ACK challenge response and any RST carry neither, so the
                // synthesis does not storm. The handshake SYN,ACK also carries SYN, so
                // per-phase arming (after ESTABLISHED) is required. The flag byte is at a
                // fixed offset, immune to the trigger's deliberately bad data offset.
                if ((flags & (kTcpFlagSyn | kTcpFlagPsh)) != 0U) {
                    emitProhibitedTcpSegment(nif, f, kTcpFlagAck);
                }
            } else {  // kTcpSynthRstOnDisruptive
                // §4.8 must-not-respond family (FLAGS_INVALID_03/04/15, FLAGS_PROCESSING_07/08,
                // CLOSING_07/08/09 — across SYN-SENT/LISTEN/EST and every close-state): the
                // conformant DUT processes or drops the segment without emitting a RST, so the
                // hook synthesizes the prohibited RST. The gate is the disruptive-flag union
                // (RST/FIN/URG/PSH), which the case's deliberate trigger carries: a bare or
                // ACK-bearing RST / out-of-window RST (FLAGS_INVALID), a URG-only segment
                // (FLAGS_PROCESSING_07), a bare FIN (FLAGS_PROCESSING_08), the PSH data segment
                // (CLOSING_07/08), or the tester's FIN (CLOSING_09). It excludes a bare pure ACK
                // and a bare SYN, so the handshake and the tester's later auto-ACKs (e.g.
                // CLOSING_08's FW1->FW2 FIN-ACK) do not trip it. The synthesized RST (seq=0)
                // trips every guard in the family — each fails on is_dut_rst, or on "any DUT
                // segment" which a RST satisfies.
                if ((flags & (kTcpFlagRst | kTcpFlagFin | kTcpFlagUrg | kTcpFlagPsh)) != 0U) {
                    emitProhibitedTcpSegment(nif, f, kTcpFlagRst);
                }
            }
        }
    }
    return g_orig_input(p, nif);
}

}  // namespace

void setIngressFaultFlavor(std::uint8_t flavor) {
    g_ingress_flavor.store(flavor, std::memory_order_relaxed);
}

void installIngressFaultHook(struct netif *nif) {
    // Null netif, or already installed: nothing to do (idempotent — never
    // double-wrap, which would corrupt the saved original input).
    if (nif == nullptr || g_orig_input != nullptr) {
        return;
    }
    g_orig_input = nif->input;
    nif->input = ingressFaultInput;
}

}  // namespace tc8::lwip_dut
