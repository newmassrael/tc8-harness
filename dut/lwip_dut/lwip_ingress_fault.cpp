// Ingress reaction-fault seam for the lwIP fixture — the netif input wrapper the
// reception `_NEG` cases drive via UT 0x19 OpSetIngressFlavor. The conformant DUT's
// reaction to an inbound frame is the property under test (it drops the frame), so
// there is no DUT egress field to corrupt; the wrapper makes the buggy DUT exhibit
// the forbidden reaction as the frame arrives:
//   * §4.2.4.2 ARP prohibited emission — synthesize the prohibited ARP Reply
//     (ARP_21/27/37/42), or wrongly learn the dropped Response's address
//     (ARP_22/28/38).
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
                   p->len >= udpRegionOffset(f) + kUdpHdrLen) {
            const std::uint16_t udp = udpRegionOffset(f);
            if (get16(f, udp + kUdpDstPort) == ut::kDataPort) {
                if (flavor == ut::kUdpFaultRejectValid) {
                    pbuf_free(p);     // swallow — the DUT wrongly drops a frame it must accept
                    return ERR_OK;
                }
                put16(f, udp + kUdpChecksum, 0x0000);  // accept-bad-checksum: skip lwIP's gate
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
