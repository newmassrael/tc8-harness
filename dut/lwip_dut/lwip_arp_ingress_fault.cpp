// TC8 §4.2.4.2 ARP ingress prohibited-emission fault for the lwIP fixture — the
// seam the reply-absence (ARP_21/27/37/42) and drop-and-emit (ARP_22/28/38) `_NEG`
// cases drive via UT 0x19 OpSetIngressFlavor. The conformant DUT drops the inbound
// malformed/foreign ARP frame and emits nothing, so there is no egress to corrupt;
// the netif input wrapper makes the buggy DUT produce the forbidden behaviour:
// synthesize the prohibited ARP Reply, or wrongly learn the dropped Response's
// address. lwIP itself is untouched — fixture glue only.
#include "lwip_arp_ingress_fault.h"

#include <atomic>
#include <cstdint>
#include <cstring>

#include "lwip/err.h"
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/tcpip.h"

#include "tc8/upper_tester_protocol.h"

#include "lwip_arp_wire.h"

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

err_t arpIngressFaultInput(struct pbuf *p, struct netif *nif) {
    const std::uint8_t flavor = g_ingress_flavor.load(std::memory_order_relaxed);
    if (flavor != ut::kIngressFaultNone && p != nullptr && p->payload != nullptr &&
        p->len >= kArpFrameLen) {
        const auto *f = static_cast<const std::uint8_t *>(p->payload);
        if (isArp(f)) {
            if (flavor == ut::kArpFaultReplyToDropFrame) {
                emitProhibitedArpReply(nif, f);
            } else if (flavor == ut::kArpFaultLearnFromDropFrame &&
                       get16(f, kArpOpcode) == 0x0002) {  // learn only from a Response
                learnDropFrameAddress(f);
            }
        }
    }
    return g_orig_input(p, nif);
}

}  // namespace

void setIngressFaultFlavor(std::uint8_t flavor) {
    g_ingress_flavor.store(flavor, std::memory_order_relaxed);
}

void installArpIngressFaultHook(struct netif *nif) {
    // Null netif, or already installed: nothing to do (idempotent — never
    // double-wrap, which would corrupt the saved original input).
    if (nif == nullptr || g_orig_input != nullptr) {
        return;
    }
    g_orig_input = nif->input;
    nif->input = arpIngressFaultInput;
}

}  // namespace tc8::lwip_dut
