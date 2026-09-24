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
//     CLOSING_07/08/09), swapped from the inbound trigger — or, for a source-port-blind demux
//     (HEADER_04), a pure ACK on the established 4-tuple recovered from an active-pcb walk, since
//     the wrong-source-port trigger does not carry the connection's real remote port to swap.
//   * §4.8.6.6 TCP must-move-to-CLOSED — DROP the inbound RST so the buggy DUT never
//     leaves SYN-SENT and keeps retransmitting its SYN (FLAGS_INVALID_05); the absence
//     of the required CLOSED transition, not a forbidden emission.
//   * §4.6.5.4 UDP prohibited acceptance — zero the inbound datagram's UDP checksum
//     so lwIP's validation gate skips and delivers it to the receive-counting app
//     (UDP_FIELDS_09/10/15).
// lwIP itself is untouched — fixture glue only.
#include "lwip_ingress_fault.h"

#include <cstdio>

#include <atomic>
#include <cstdint>
#include <cstring>

#include "lwip/err.h"
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include "lwip/tcpip.h"
// tcp_active_pcbs (the ESTABLISHED-pcb list the source-port-blind synth walks) and the
// full tcp_pcb / enum tcp_state definitions live in this private header. Its extern "C"
// block covers every declaration, so no wrapper (matches lwip_stack_probe.cpp).
#include "lwip/priv/tcp_priv.h"

#include "tc8/upper_tester_protocol.h"
#include "tc8/wire/ip_checksum.h"

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

// Frames seen by this hook, and how many of them tcpip_input REFUSED. The hook
// sits on the only boundary lwIP does not count: tapif's read() is above it and
// ip4_reass() is below, and a fragment lost between the two is invisible to every
// lwIP statistic (pbuf pool, heap, ip_frag, tcpip mbox are all clean while
// fragments go missing). `tcpip_input` posts NON-BLOCKING and silently frees the
// pbuf on a full mailbox, so this counter is what tells "the tap never delivered
// it" apart from "lwIP refused it after delivery".
std::atomic<std::uint32_t> g_rx_frames{0};
std::atomic<std::uint32_t> g_rx_ipv4_frags{0};
std::atomic<std::uint32_t> g_input_refused{0};

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

// kIcmpFaultSynthTimestampReplyBadSeq: a buggy DUT answering a §4.3.3.2 Timestamp Request
// (type 13) with a Reply (type 14) that echoes the identifier but NOT the sequence. It is a
// synthesis rather than an egress corruption because lwIP implements no Timestamp at all —
// icmp.c counts ICMP_TS and drops — so there is no emitted reply to corrupt, and the positive
// is a platform_known_fail here for that reason.
//
// A full 20-byte Timestamp body is built rather than the 8-byte minimum the Echo-family synth
// above uses: RFC 792 p17 defines the message through the transmit timestamp, and the sibling
// emitter's contract is that the frame is valid at every layer rather than merely dissectable.
// The three timestamps stay zero — no guard reads them, and a zeroed millisecond-since-midnight
// is a legal value, so leaving them is not a malformation.
//
// ⚠ The identifier is echoed DELIBERATELY. ICMPv4_TYPE_12 guards the identifier and the
// sequence with separate finals and one run reaches one final; echoing the identifier is what
// makes the run fall through to the sequence guard, which is the one no negative row can reach.
void emitTimestampReplyBadSeq(struct netif *nif, const std::uint8_t *rx) {
    constexpr std::uint16_t kL4Off    = kEthHdrLen + kIpHdrLenMin;        // 34
    constexpr std::uint16_t kFrameLen = kL4Off + kIcmpTimestampLen;       // 54
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
    put16(o, kIpTotalLenOff, kIpHdrLenMin + kIcmpTimestampLen);
    o[kIpTtlOff]   = 64;
    o[kIpProtoOff] = kIpProtoIcmp;
    const std::uint32_t dut_ip = ip4_addr_get_u32(netif_ip4_addr(nif));
    std::memcpy(o + kIpSrcOff, &dut_ip, 4);               // src = DUT IP (network order)
    std::memcpy(o + kIpDstOff, rx + kIpSrcOff, 4);        // dst = trigger's IPv4 src (the tester)
    put16(o, kIpHdrChecksumOff, ::tc8::wire::inetChecksum(o + kEthHdrLen, kIpHdrLenMin));
    o[kL4Off + kIcmpTypeOff] = kIcmpTypeTimestampReply;
    put16(o, kL4Off + kIcmpEchoIdOff, get16(rx, kL4Off + kIcmpEchoIdOff));  // echoed, on purpose
    // The corruption: the sequence the case requires to be echoed verbatim, returned inverted
    // so it cannot collide with the requested value whatever the tester chose.
    put16(o, kL4Off + kIcmpEchoSeqOff,
          static_cast<std::uint16_t>(~get16(rx, kL4Off + kIcmpEchoSeqOff)));
    put16(o, kL4Off + kIcmpChecksumOff, ::tc8::wire::inetChecksum(o + kL4Off, kIcmpTimestampLen));
    nif->linkoutput(nif, p);
    pbuf_free(p);
}

// emitTcpReply: build + emit a 20-byte TCP segment (no options, no payload) on an explicit
// (src_port, dst_port) 4-tuple, addressed back to the inbound trigger's sender with the DUT's
// own source identity — the source IP is the DUT's own netif address so a multicast-destination
// trigger (HEADER_11) still yields a DUT-sourced reply. seq/ack stay 0: the §4.8 guards
// (is_dut_rst / is_pure_dut_ack) read only the 4-tuple + flag, never seq/ack (a real segment's
// seq is connection-state-derived, which this hook does not track). Both checksums use the shared
// tc8::wire SSOT (IPv4 header via inetChecksum, TCP via tcpChecksum's pseudo-header fold) so the
// frame is valid at every layer. The frame-build core both TCP synthesis callers below share;
// sent via nif->linkoutput like the ARP/ICMP synthesis.
void emitTcpReply(struct netif *nif, const std::uint8_t *rx,
                  std::uint16_t src_port, std::uint16_t dst_port, std::uint8_t tcp_flags) {
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
    put16(o, kL4Off + kTcpSrcPortOff, src_port);
    put16(o, kL4Off + kTcpDstPortOff, dst_port);
    o[kL4Off + kTcpDataOffOff] = 0x50;                    // data offset 5 (20 B header, no options)
    o[kL4Off + kTcpFlagsOff]   = tcp_flags;               // RST or ACK
    put16(o, kL4Off + kTcpChecksumOff,
          ::tc8::wire::tcpChecksum(dut_ip, tester_ip, o + kL4Off, kTcpMinHdrLen));
    nif->linkoutput(nif, p);
    pbuf_free(p);
}

// kTcpSynth*: a buggy DUT emitting a forbidden TCP response to a segment it must silently
// accept or drop — a RST on a pure ACK in ESTABLISHED (kTcpSynthRst, §4.8.6.18
// ACKNOWLEDGEMENT_04 + §4.8.6.7 FLAGS_PROCESSING_11), a challenge ACK on a malformed/multicast
// segment (kTcpSynthAck, §4.8.6.16 HEADER_07/08/09/11), or a RST on a disruptive segment the
// DUT must answer with silence (kTcpSynthRstOnDisruptive, the §4.8 must-not-respond family —
// FLAGS_INVALID_03/04/15, FLAGS_PROCESSING_07/08, CLOSING_07/08/09). `rx` points at the inbound
// trigger; the synthesized segment carries `tcp_flags` on the connection's 4-tuple, derived by
// swapping the trigger's source for the destination.
void emitProhibitedTcpSegment(struct netif *nif, const std::uint8_t *rx, std::uint8_t tcp_flags) {
    const std::uint16_t rx_l4 = l4RegionOffset(rx);
    emitTcpReply(nif, rx,
                 /*src_port=*/get16(rx, rx_l4 + kTcpDstPortOff),   // src = DUT local port
                 /*dst_port=*/get16(rx, rx_l4 + kTcpSrcPortOff),   // dst = tester remote port (swap)
                 tcp_flags);
}

// kTcpSynthAckSrcPortBlind (§4.8.6.16 HEADER_04): a buggy DUT that demultiplexes an inbound data
// segment by its local (destination) port alone, ignoring the source port — so it accepts and
// ACKs a segment whose source port differs from the established peer's, which a conformant DUT
// (RFC 793 §3.1 / §3.9 full-4-tuple demux) drops silently. The connection's real remote port is
// NOT in the trigger (the trigger's source port is the wrong one), so emitProhibitedTcpSegment's
// port swap would reply to that wrong port — never the EST 4-tuple the positive's is_pure_dut_ack
// guard watches. Instead walk tcp_active_pcbs (read-only, under the core lock — this rx thread is
// not the tcpip thread, the learnDropFrameAddress precedent) for the ESTABLISHED connection on the
// segment's destination port whose remote port differs from the segment's source port (i.e. the
// segment arrived from the wrong source port), then synthesize the prohibited pure ACK on that
// connection's real 4-tuple (src = its local port = the segment's dst port, dst = its remote port).
void emitSrcPortBlindAck(struct netif *nif, const std::uint8_t *rx) {
    const std::uint16_t rx_l4      = l4RegionOffset(rx);
    const std::uint16_t local_port = get16(rx, rx_l4 + kTcpDstPortOff);  // DUT local port (segment dst)
    const std::uint16_t wrong_src  = get16(rx, rx_l4 + kTcpSrcPortOff);  // the deliberately-wrong tester port
    std::uint16_t conn_remote_port = 0;
    bool found = false;
    LOCK_TCPIP_CORE();
    for (const struct tcp_pcb *pcb = tcp_active_pcbs; pcb != nullptr; pcb = pcb->next) {
        if (pcb->state == ESTABLISHED && pcb->local_port == local_port &&
            pcb->remote_port != wrong_src) {  // a segment for this connection from the WRONG source port
            conn_remote_port = pcb->remote_port;
            found = true;
            break;
        }
    }
    UNLOCK_TCPIP_CORE();
    if (found) {
        emitTcpReply(nif, rx, /*src_port=*/local_port, /*dst_port=*/conn_remote_port, kTcpFlagAck);
    }
}

// kArpFaultLearnFromDropFrame: a buggy DUT that wrongly accepted a malformed/foreign
// ARP Response it should have dropped (§4.2.4.2 ARP_22/28/38 drop-and-emit). `rx`
// points at the inbound frame; its (sender_ip -> sender_hw) is forced into the ARP
// table as a static entry, so the DUT's subsequent UT-provoked UDP egress resolves
// straight to the dropped frame's MAC instead of emitting its own ARP Request — the
// exact violation the positive guard forbids. Under the core lock: this rx thread is
// not the tcpip thread, so it must hold it to touch the ARP table.
// True when THIS HOOK has already passed a teaching Request for the same sender IP since
// the flavour was armed — what tells a SECOND teaching of an address from the first, and
// so what kArpFaultIgnoreUpdate is gated on.
//
// ⚠ It does NOT ask the ARP table, and the first version did. MEASURED 2026-09-24: asking
// `etharp_find_addr` made the stale-MAC negative inert. This hook runs on the rx thread while
// `tcpip_input` hands the frame to the tcpip thread asynchronously, so when the second
// teaching arrives microseconds after the first, the table has not necessarily been
// updated yet and the lookup answers "not held" — the very frame to swallow passes
// through. Remembering what the hook itself forwarded has no such race, and it is also
// the more faithful reading of "ignore an UPDATE": the update is the second teaching,
// whatever the stack has managed to do with the first.
std::uint32_t g_first_taught_ip = 0;
bool          g_have_first_taught = false;

// kIpv4FaultHoldFirstFragment's deferred head. A COPY of the frame rather than the pbuf
// itself: holding a borrowed pbuf across an unbounded wire gap would keep a stack buffer
// checked out of the pool for seconds, and the whole point of the seam is that the gap is
// long. The copy is replayed into a fresh pbuf when the tail arrives, so ownership never
// crosses the hook boundary. One slot, because the flavor exists for a single two-fragment
// phase; a second head before the tail simply replaces it, which is the honest behaviour
// (the newest head is the one whose tail is still coming).
constexpr std::uint16_t kHeldFragmentCap = 1600;  // an Ethernet frame plus slack
std::uint8_t  g_held_fragment[kHeldFragmentCap];
std::uint16_t g_held_fragment_len = 0;

bool senderAlreadyTaught(const std::uint8_t *rx) {
    std::uint32_t ip = 0;
    std::memcpy(&ip, rx + kArpSenderIp, 4);  // network order
    if (g_have_first_taught && ip == g_first_taught_ip) return true;
    g_first_taught_ip = ip;
    g_have_first_taught = true;
    return false;
}

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
    g_rx_frames.fetch_add(1, std::memory_order_relaxed);
    if (p != nullptr && p->payload != nullptr && p->len >= kIpProtoOff + 1) {
        const auto *hdr = static_cast<const std::uint8_t *>(p->payload);
        // An IPv4 fragment: MF set, or a non-zero fragment offset. Counted here so
        // "the tap delivered every fragment" can be stated as a number rather than
        // inferred from the tester's capture, which only proves what was SENT.
        if (isIpv4(hdr) && (hdr[kEthHdrLen + 6] & 0x20U) != 0U) {
            g_rx_ipv4_frags.fetch_add(1, std::memory_order_relaxed);
        } else if (isIpv4(hdr) &&
                   ((static_cast<std::uint16_t>(hdr[kEthHdrLen + 6] & 0x1FU) << 8) |
                    hdr[kEthHdrLen + 7]) != 0U) {
            g_rx_ipv4_frags.fetch_add(1, std::memory_order_relaxed);
        }
    }
    const std::uint8_t flavor = g_ingress_flavor.load(std::memory_order_relaxed);
    if (flavor != ut::kIngressFaultNone && p != nullptr && p->payload != nullptr) {
        auto *f = static_cast<std::uint8_t *>(p->payload);
        if (p->len >= kArpFrameLen && isArp(f)) {
            if (flavor == ut::kArpFaultReplyToDropFrame) {
                emitProhibitedArpReply(nif, f);
            } else if (flavor == ut::kArpFaultLearnFromDropFrame &&
                       get16(f, kArpOpcode) == 0x0002) {  // learn only from a Response
                learnDropFrameAddress(f);
            } else if (get16(f, kArpOpcode) == 0x0001 &&  // a teaching REQUEST only
                       (flavor == ut::kArpFaultIgnoreLearn ||
                        (flavor == ut::kArpFaultIgnoreUpdate && senderAlreadyTaught(f)))) {
                // Swallow the frame so lwIP's etharp never sees it and the cache keeps
                // whatever it held. Ignore-learn takes any teaching Request, so the
                // taught address is never held and the DUT resolves by emitting its own
                // Request; ignore-update takes only one re-teaching an address already
                // held, so the FIRST MAC survives and egress goes to the stale one.
                // Freeing here is the same swallow kTcpDropDisruptiveRst and
                // kIpv4FaultDropLastFragment do.
                //
                // ⚠ OPCODE 1 ONLY, and that is not a narrowing for tidiness. This DUT
                // ARP-resolves the tester for its OWN UT control-plane ACKs, and the
                // tester answers that with an ARP RESPONSE. Swallowing responses too
                // would starve the control channel, so the case could never report
                // anything and the fault would look inert rather than effective. The
                // teaching frames these flavors target are Requests
                // (emitArpLearningBoot, ArpLearningVariant::Request); a gratuitous
                // Response teaching is the sibling kArpFaultLearnFromDropFrame's half.
                pbuf_free(p);
                return ERR_OK;
            } else if (flavor == ut::kArpFaultIgnoreGratuitous &&
                       get16(f, kArpOpcode) == 0x0002 &&
                       std::memcmp(f + kArpSenderIp, f + kArpTargetIp, 4) == 0) {
                // §4.2.4.1 ARP_34: the opcode-2 counterpart of the ignore-update sibling above.
                // TD-32 records that lwIP etharp UPDATES an existing entry from a gratuitous
                // Response although it never creates one, and ARP_34's pass rides exactly that
                // update — its opening Request teaches MAC1, its gratuitous Response carries
                // MAC2 over it. Swallowing the Response leaves MAC1 held, so the DUT addresses
                // its egress to the stale MAC, which is the final the positive forbids.
                //
                // ⚠ target_ip == sender_ip is the control-plane gate, not a shape filter. The
                // sibling flavors take Requests only because swallowing every Response would
                // eat the tester's answer to the DUT's own resolution and starve the UT
                // channel; a tester answering a Request addresses it to the DUT, so that frame
                // is never gratuitous and never reaches this branch.
                pbuf_free(p);
                return ERR_OK;
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
                    flavor == ut::kIcmpFaultSynthParamProblem ||
                    flavor == ut::kIcmpFaultSynthTimeExceeded) &&
                   p->len >= kEthHdrLen + kIpHdrLenMin && isIpv4(f) &&
                   f[kIpProtoOff] == kIpProtoIcmp) {
            // §4.3 ICMP prohibited emission, and the §4.4 IPv4-header must-not-reply guards
            // that reuse the Echo Reply synth: the conformant DUT drops the trigger and stays
            // silent, so the input hook synthesizes the forbidden ICMP reply. The flavor
            // names the reply type; the original frame still goes to lwIP, which drops it.
            // TimeExceeded (TYPE_04) fires whatever the trigger's fragment offset — the hook
            // reads only fixed-offset fields, so an offset>0 lone fragment still synthesizes it.
            const std::uint8_t reply_type =
                flavor == ut::kIcmpFaultSynthInfoReply    ? kIcmpTypeInfoReply :
                flavor == ut::kIcmpFaultSynthParamProblem ? kIcmpTypeParamProblem :
                flavor == ut::kIcmpFaultSynthTimeExceeded ? kIcmpTypeTimeExceeded :
                                                            kIcmpTypeEchoReply;
            emitProhibitedIcmpReply(nif, f, reply_type);
        } else if (flavor == ut::kIcmpFaultSynthTimestampReplyBadSeq &&
                   p->len >= kEthHdrLen + kIpHdrLenMin && isIpv4(f) &&
                   f[kIpProtoOff] == kIpProtoIcmp &&
                   p->len >= l4RegionOffset(f) + kIcmpMinHdrLen &&
                   f[l4RegionOffset(f) + kIcmpTypeOff] == kIcmpTypeTimestamp) {
            // §4.3.3.2 TYPE_12: a buggy DUT that answers a Timestamp Request without echoing
            // the sequence. Gated on the trigger's ICMP type rather than on ICMP alone, so the
            // Echo traffic the fixture's other cases carry is never answered twice. The
            // original frame still goes to lwIP, which drops it (ICMP_TS is counted and
            // discarded) — the synthesized reply is the only type 14 on the wire.
            emitTimestampReplyBadSeq(nif, f);
        } else if ((flavor == ut::kTcpSynthRst || flavor == ut::kTcpSynthAck ||
                    flavor == ut::kTcpSynthRstOnDisruptive ||
                    flavor == ut::kTcpSynthFinOnDisruptive) &&
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
            } else if (flavor == ut::kTcpSynthRstOnDisruptive) {
                // §4.8 must-not-respond family (across LISTEN / SYN-SENT / SYN-RCVD /
                // ESTABLISHED / every close-state / the closed port): the
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
            } else {  // kTcpSynthFinOnDisruptive
                // §4.8.6.4 CALL_RECEIVE_05: the conformant DUT in CLOSE-WAIT (after the PSH+FIN
                // data segment) returns the queued data on a RECEIVE call and stays in CW
                // without emitting a FIN before the application closes (RFC 793 §3.5). The hook
                // synthesizes the prohibited FIN+ACK on the same disruptive-flag gate as the
                // RST sibling, so the dut_emitted_fin_in_cw_without_close fail-final (is_dut_fin_ack)
                // is reachable. FIN+ACK (not a bare FIN) matches is_dut_fin_ack; the pure-ACK and
                // bare-SYN exclusion keeps the handshake and auto-ACKs clear, exactly as the RST
                // sibling.
                if ((flags & (kTcpFlagRst | kTcpFlagFin | kTcpFlagUrg | kTcpFlagPsh)) != 0U) {
                    emitProhibitedTcpSegment(nif, f, kTcpFlagFin | kTcpFlagAck);
                }
            }
        } else if (flavor == ut::kTcpDropDisruptiveRst &&
                   p->len >= kEthHdrLen + kIpHdrLenMin && isIpv4(f) &&
                   f[kIpProtoOff] == kIpProtoTcp &&
                   p->len >= l4RegionOffset(f) + kTcpMinHdrLen) {
            // §4.8.6.6 FLAGS_INVALID_05: a buggy DUT in SYN-SENT that fails to move to
            // CLOSED on an inbound RST + acceptable ACK. The conformant DUT processes the
            // RST, cancels its SYN retransmit, and goes silent; this hook swallows the
            // RST-bearing segment before lwIP's TCP sees it, so lwIP stays in SYN-SENT and
            // keeps retransmitting its SYN at the fixed 1 s cadence — the continued-SYN
            // violation the positive's 3 s absence window forbids. Drop seam (pbuf_free,
            // never forwarded — the kUdpFaultRejectValid sibling), not a tcp_in.c patch. The
            // gate is the RST flag, which both the phase-1 SYN+ACK+RST and phase-2 ACK+RST
            // probes carry; lwIP's own SYN retransmits are egress (not seen by this input
            // hook) and the UDP UT arm frame is not TCP, so only the injected RST is dropped.
            const std::uint16_t tcp = l4RegionOffset(f);
            if ((f[tcp + kTcpFlagsOff] & kTcpFlagRst) != 0U) {
                pbuf_free(p);  // swallow — the DUT wrongly ignores a RST it must act on
                return ERR_OK;
            }
        } else if (flavor == ut::kIpv4FaultDropLastFragment &&
                   p->len >= kEthHdrLen + kIpHdrLenMin && isIpv4(f)) {
            // §4.4.4.7 REASSEMBLY_11 / _13: a buggy DUT that loses the last fragment of a
            // datagram it must reassemble. The conformant DUT completes the bucket and
            // answers the Echo Request; this hook swallows the tail (MF clear, offset
            // non-zero) before ip4_reass sees it, so lwIP's bucket expires and lwIP itself
            // sends the Time Exceeded code 1 that quotes the head fragment — the discard
            // report the positive grades as a fail. Drop seam (pbuf_free, never forwarded
            // — the kTcpDropDisruptiveRst sibling), not an ip4_frag.c patch. The head and
            // any middle fragment carry MF, and an unfragmented frame (the UT arm
            // included) has offset 0, so neither is touched.
            const bool more_fragments = (f[kEthHdrLen + 6] & 0x20U) != 0U;
            const std::uint16_t frag_offset = static_cast<std::uint16_t>(
                (static_cast<std::uint16_t>(f[kEthHdrLen + 6] & 0x1FU) << 8) | f[kEthHdrLen + 7]);
            if (!more_fragments && frag_offset != 0U) {
                pbuf_free(p);  // swallow — the DUT wrongly loses a fragment it must keep
                return ERR_OK;
            }
        } else if (flavor == ut::kIpv4FaultNormaliseFragTuple &&
                   p->len >= kEthHdrLen + kIpHdrLenMin && isIpv4(f)) {
            // §4.4.4.6 FRAGMENTS_02/03/04: a buggy DUT that reassembles fragments whose
            // reassembly tuple does not match. The head fragment (offset 0, MF set) is
            // the anchor; every later fragment of the burst adopts its id, source and
            // protocol, so lwIP sees a matching pair and completes the bucket while the
            // WIRE still carried the mismatch the tester injected. The DUT then answers
            // the Echo, which is the violation each positive grades.
            //
            // Mutate seam, so the IPv4 header checksum MUST be recomputed — lwIP
            // validates it and a stale one would make the frame vanish and the fault
            // read as inert. Unfragmented traffic (the UT control channel included) has
            // MF clear and offset 0, so it is never touched.
            const bool more_fragments = (f[kEthHdrLen + 6] & 0x20U) != 0U;
            const std::uint16_t frag_offset = static_cast<std::uint16_t>(
                (static_cast<std::uint16_t>(f[kEthHdrLen + 6] & 0x1FU) << 8) | f[kEthHdrLen + 7]);
            if (more_fragments || frag_offset != 0U) {
                static std::uint8_t anchor[7];  // id(2) | proto(1) | src(4)
                static bool have_anchor = false;
                if (frag_offset == 0U) {
                    std::memcpy(anchor, f + kEthHdrLen + 4, 2);
                    anchor[2] = f[kIpProtoOff];
                    std::memcpy(anchor + 3, f + kIpSrcOff, 4);
                    have_anchor = true;
                } else if (have_anchor) {
                    std::memcpy(f + kEthHdrLen + 4, anchor, 2);
                    f[kIpProtoOff] = anchor[2];
                    std::memcpy(f + kIpSrcOff, anchor + 3, 4);
                    put16(f, kIpHdrChecksumOff, 0);
                    put16(f, kIpHdrChecksumOff,
                          ::tc8::wire::inetChecksum(f + kEthHdrLen, kIpHdrLenMin));
                }
            }
        } else if (flavor == ut::kIpv4FaultHoldFirstFragment &&
                   p->len >= kEthHdrLen + kIpHdrLenMin && isIpv4(f)) {
            // §4.4.4.7 REASSEMBLY_10 phase B: a buggy DUT whose reassembly timer is too long,
            // so a pair the wire spread ACROSS the window still completes and is answered —
            // the emission phase B forbids once its bucket has expired. A DEFER seam: the head
            // is copied and swallowed, then replayed immediately ahead of its tail, so ip4_reass
            // meets the two back-to-back however long the gap was. Nothing is rewritten, so no
            // checksum is owed at any layer.
            //
            // ⚠ The obvious shortcut — clear MF so the head reads as a whole datagram — was
            // MEASURED INERT on 2026-09-25, and not for a timing reason: the head carries the
            // ICMP checksum of the WHOLE message, so a truncated datagram fails
            // CHECKSUM_CHECK_ICMP in icmp_input and is dropped in silence. Recomputing that
            // checksum would not rescue it, because a stack that genuinely mishandles MF hands
            // icmp_input the same stale checksum and drops it too. That shortcut cannot produce
            // this guard's observable on ANY stack, which is why the seam defers a frame.
            //
            // ⚠ Fragments only (MF set, or a non-zero offset). An unfragmented frame — the UT
            // control channel and the arm itself included — matches neither arm and passes.
            const bool more_fragments = (f[kEthHdrLen + 6] & 0x20U) != 0U;
            const std::uint16_t frag_offset = static_cast<std::uint16_t>(
                (static_cast<std::uint16_t>(f[kEthHdrLen + 6] & 0x1FU) << 8) | f[kEthHdrLen + 7]);
            if (more_fragments && frag_offset == 0U && p->len <= kHeldFragmentCap) {
                std::memcpy(g_held_fragment, f, p->len);
                g_held_fragment_len = p->len;
                pbuf_free(p);  // swallow the head; the tail's arrival is what releases it
                return ERR_OK;
            }
            if (!more_fragments && frag_offset != 0U && g_held_fragment_len != 0U) {
                struct pbuf *head = pbuf_alloc(PBUF_RAW, g_held_fragment_len, PBUF_RAM);
                if (head != nullptr) {
                    std::memcpy(head->payload, g_held_fragment, g_held_fragment_len);
                    g_held_fragment_len = 0;
                    // Straight to the saved input, not back through this hook: the replay must
                    // not be deferred a second time, and the counters above already counted
                    // this frame when the wire delivered it.
                    g_orig_input(head, nif);
                }
            }
        } else if (flavor == ut::kTcpSynthAckSrcPortBlind &&
                   p->len >= kEthHdrLen + kIpHdrLenMin && isIpv4(f) &&
                   f[kIpProtoOff] == kIpProtoTcp &&
                   p->len >= l4RegionOffset(f) + kTcpMinHdrLen) {
            // §4.8.6.16 HEADER_04: a buggy DUT that ACKs an in-window data segment whose source
            // port differs from the established peer's (source-port-blind demux). The gate here is
            // an ACK-bearing data segment (the wrong-port PSH+ACK trigger carries payload); the
            // pcb walk inside emitSrcPortBlindAck then fires only when an ESTABLISHED connection
            // exists on the segment's destination port whose remote port differs from the segment's
            // source port — so the handshake's control segments and any right-source-port segment
            // (remote_port == source) never synthesize, only the deliberate wrong-port inject does.
            const std::uint16_t tcp = l4RegionOffset(f);
            if ((f[tcp + kTcpFlagsOff] & kTcpFlagAck) != 0U && tcpHasPayload(f, tcp)) {
                emitSrcPortBlindAck(nif, f);
            }
        }
    }
    const err_t rc = g_orig_input(p, nif);
    if (rc != ERR_OK) {
        // tcpip_input refused it (full mailbox — it posts non-blocking and frees
        // the pbuf itself). lwIP counts this nowhere, so it is counted here.
        g_input_refused.fetch_add(1, std::memory_order_relaxed);
    }
    return rc;
}

}  // namespace

void setIngressFaultFlavor(std::uint8_t flavor) {
    // Arming resets the per-arm memory kArpFaultIgnoreUpdate keeps, so a second case in
    // the same DUT lifetime does not inherit the first case's "already taught" sender
    // and swallow its FIRST teaching.
    g_have_first_taught = false;
    g_first_taught_ip = 0;
    // Likewise kIpv4FaultHoldFirstFragment's deferred head: a head swallowed by one case and
    // never released (its tail lost, or the case ended between the two) must not be replayed
    // into the next case's first tail.
    g_held_fragment_len = 0;
    g_ingress_flavor.store(flavor, std::memory_order_relaxed);
}

void reportIngressRxCounters() {
    std::fprintf(stderr,
                 "tc8-lwip-dut: rx_frames=%u rx_ipv4_frags=%u input_refused=%u\n",
                 g_rx_frames.load(std::memory_order_relaxed),
                 g_rx_ipv4_frags.load(std::memory_order_relaxed),
                 g_input_refused.load(std::memory_order_relaxed));
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
