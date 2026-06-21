#include "lwip_arp_fault.h"

#include <atomic>
#include <cstdint>

#include "lwip/err.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"

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

}  // namespace tc8::lwip_dut
