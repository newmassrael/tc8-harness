// TC8 §4.2 ARP fault injection for the lwIP fixture. Two fault kinds the §4.2 ARP
// `_NEG` self-validation cases drive via UT 0x18 OpSetArpFlavor, both fixture glue
// with lwIP itself untouched:
//   * EGRESS field-corruption — the netif link-output wrapper rewrites one header
//     field of a DUT-emitted ARP frame (the §4.2 ARP field cases).
//   * INGRESS prohibited-emission — the netif input wrapper makes a buggy DUT
//     produce the behaviour a §4.2.4.2 reception case proves absent, since the
//     conformant DUT drops the frame and emits nothing to corrupt: synthesize the
//     forbidden ARP Reply (reply-absence), or wrongly learn the dropped Response's
//     address into the ARP table (drop-and-emit) so a later UDP egress uses it.
// Carries the ARP-over-Ethernet field offsets, the deterministic wrong-value
// sentinels, and both netif wrappers.
#include "lwip_arp_fault.h"

#include <atomic>
#include <cstdint>
#include <cstring>

#include "lwip/err.h"
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/tcpip.h"

#include "tc8/upper_tester_protocol.h"

namespace tc8::lwip_dut {
namespace {

namespace ut = ::tc8::ut;

// The active flavor: written on the UT thread (OpSetArpFlavor handler), read on the
// tcpip thread (the egress hook). Atomic with relaxed ordering is sufficient — it
// gates only our own byte rewrite of an outgoing frame, never lwIP state, so there
// is no other memory to synchronise against.
std::atomic<std::uint8_t> g_arp_fault_flavor{ut::kArpFaultNone};

// The netif's original tap link-output, saved at install. The hook forwards to it
// after (optionally) corrupting the ARP header.
netif_linkoutput_fn g_orig_linkoutput = nullptr;

// Ethernet(14) + ARP field offsets within the link-output frame. ARP-over-Ethernet
// carries no checksum and the tap/driver appends the FCS, so a field rewrite needs
// no fix-up.
constexpr std::uint16_t kEthTypeOff = 12;  // u16 ethertype       (0x0806 == ARP)
constexpr std::uint16_t kArpHType   = 14;  // u16 hardware type   (1 = Ethernet)
constexpr std::uint16_t kArpPType   = 16;  // u16 protocol type   (0x0800 = IPv4)
constexpr std::uint16_t kArpHLen    = 18;  // u8  hw addr length  (6)
constexpr std::uint16_t kArpPLen    = 19;  // u8  proto addr len  (4)
constexpr std::uint16_t kArpOpcode  = 20;  // u16 opcode          (1 request / 2 reply)
constexpr std::uint16_t kArpMinLen  = 22;  // bytes needed through the opcode field
constexpr std::uint16_t kArpSenderHw = 22;  // 6  sender hardware addr
constexpr std::uint16_t kArpSenderIp = 28;  // 4  sender protocol addr
constexpr std::uint16_t kArpTargetHw = 32;  // 6  target hardware addr
constexpr std::uint16_t kArpTargetIp = 38;  // 4  target protocol addr
constexpr std::uint16_t kArpFrameLen = 42;  // Ethernet(14) + ARP(28) for IPv4/Ethernet

// Deterministic non-conformant sentinels. The matching ARP_xx guard tests
// `field != correct`, so the exact wrong value is immaterial; these are unambiguous
// RFC 826 violations (and not the "no observation" timeout the guard also has).
constexpr std::uint16_t kWrongHType  = 0x0006;  // IEEE 802, not Ethernet (1)
constexpr std::uint16_t kWrongPType  = 0x86DD;  // IPv6, not IPv4 (0x0800)
constexpr std::uint8_t  kWrongHLen   = 0x08;    // not 6
constexpr std::uint8_t  kWrongPLen   = 0x06;    // not 4
constexpr std::uint16_t kWrongOpcode = 0x0009;  // neither request (1) nor reply (2)

void put16(std::uint8_t *f, std::uint16_t off, std::uint16_t v) {
    f[off] = static_cast<std::uint8_t>(v >> 8);
    f[off + 1] = static_cast<std::uint8_t>(v & 0xFF);
}

std::uint16_t get16(const std::uint8_t *f, std::uint16_t off) {
    return static_cast<std::uint16_t>(f[off] << 8) | f[off + 1];
}

bool isArp(const std::uint8_t *f) {
    return f[kEthTypeOff] == 0x08 && f[kEthTypeOff + 1] == 0x06;
}

void mutateArp(std::uint8_t *f, std::uint8_t flavor) {
    switch (flavor) {
        case ut::kArpFaultHwTypeWrong:    put16(f, kArpHType, kWrongHType);   break;
        case ut::kArpFaultProtoTypeWrong: put16(f, kArpPType, kWrongPType);   break;
        case ut::kArpFaultHwLenWrong:     f[kArpHLen] = kWrongHLen;           break;
        case ut::kArpFaultProtoLenWrong:  f[kArpPLen] = kWrongPLen;           break;
        case ut::kArpFaultOpcodeWrong:    put16(f, kArpOpcode, kWrongOpcode); break;
        default:                          break;  // kArpFaultNone / unknown: no-op
    }
}

err_t arpFaultLinkoutput(struct netif *nif, struct pbuf *p) {
    const std::uint8_t flavor = g_arp_fault_flavor.load(std::memory_order_relaxed);
    if (flavor != ut::kArpFaultNone && p != nullptr && p->payload != nullptr &&
        p->len >= kArpMinLen) {
        auto *f = static_cast<std::uint8_t *>(p->payload);
        if (isArp(f)) {
            mutateArp(f, flavor);
        }
    }
    return g_orig_linkoutput(nif, p);
}

// The netif's original input (tcpip_input), saved at ingress-hook install. Every
// inbound frame is forwarded to it after (optionally) producing the prohibited
// emission, so lwIP's own reception (which drops the malformed/foreign frame) is
// unchanged.
netif_input_fn g_orig_input = nullptr;

// kArpFaultReplyToDropFrame: a buggy DUT answering an ARP frame it should have
// dropped (§4.2.4.2 ARP_21/27/37/42 reply-absence). `rx` points at the inbound
// Ethernet+ARP frame; the synthesized Reply is addressed back to its sender with
// the DUT's own identity, so the case guard's `opcode == 2 and sender_hw ==
// dut_iface_mac` fires. Sent via the saved RAW link-output (not nif->linkoutput)
// so the egress field-corruption hook never touches it. No core lock needed: the
// tap link-output is a stack-buffered write(2), and pbuf_alloc on this (rx) thread
// is what low_level_input already does for every inbound frame.
void emitProhibitedArpReply(struct netif *nif, const std::uint8_t *rx) {
    if (g_orig_linkoutput == nullptr) {
        return;  // ingress hook installed before the egress hook saved the original
    }
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
    g_orig_linkoutput(nif, p);
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

err_t arpFaultIngressInput(struct pbuf *p, struct netif *nif) {
    const std::uint8_t flavor = g_arp_fault_flavor.load(std::memory_order_relaxed);
    if (flavor != ut::kArpFaultNone && p != nullptr && p->payload != nullptr &&
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

void setArpFaultFlavor(std::uint8_t flavor) {
    g_arp_fault_flavor.store(flavor, std::memory_order_relaxed);
}

void installArpFaultEgressHook(struct netif *nif) {
    // Null netif, or already installed: nothing to do (idempotent — never double-wrap,
    // which would corrupt the saved original).
    if (nif == nullptr || g_orig_linkoutput != nullptr) {
        return;
    }
    g_orig_linkoutput = nif->linkoutput;
    nif->linkoutput = arpFaultLinkoutput;
}

void installArpFaultIngressHook(struct netif *nif) {
    // Null netif, or already installed: nothing to do (idempotent — never
    // double-wrap, which would corrupt the saved original input).
    if (nif == nullptr || g_orig_input != nullptr) {
        return;
    }
    g_orig_input = nif->input;
    nif->input = arpFaultIngressInput;
}

}  // namespace tc8::lwip_dut
