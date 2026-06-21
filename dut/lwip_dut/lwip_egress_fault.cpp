// Egress field-fault injection for the lwIP fixture — the generic seam the field-
// shape `_NEG` self-validation cases drive via UT 0x18 OpSetEgressFlavor. The netif
// link-output wrapper rewrites one header field of a DUT-emitted frame (and
// recomputes the affected checksum), routed by the armed flavor; lwIP itself is
// untouched. Protocol-generic: the §4.2 ARP-over-Ethernet fields today (no
// checksum), with IPv4/UDP/TCP/ICMP joining the same hook and one flavor catalog.
#include "lwip_egress_fault.h"

#include <atomic>
#include <cstdint>

#include "lwip/err.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"

#include "tc8/upper_tester_protocol.h"

#include "lwip_arp_wire.h"

namespace tc8::lwip_dut {
namespace {

namespace ut = ::tc8::ut;

// The active flavor: written on the UT thread (OpSetEgressFlavor handler), read on
// the tcpip thread (the link-output hook). Atomic with relaxed ordering is
// sufficient — it gates only our own byte rewrite of an outgoing frame, never lwIP
// state, so there is no other memory to synchronise against.
std::atomic<std::uint8_t> g_egress_flavor{ut::kEgressFaultNone};

// The netif's original tap link-output, saved at install. The hook forwards to it
// after (optionally) corrupting the header.
netif_linkoutput_fn g_orig_linkoutput = nullptr;

// Deterministic non-conformant ARP sentinels. The matching ARP_xx guard tests
// `field != correct`, so the exact wrong value is immaterial; these are unambiguous
// RFC 826 violations (and not the "no observation" timeout the guard also has).
constexpr std::uint16_t kWrongHType  = 0x0006;  // IEEE 802, not Ethernet (1)
constexpr std::uint16_t kWrongPType  = 0x86DD;  // IPv6, not IPv4 (0x0800)
constexpr std::uint8_t  kWrongHLen   = 0x08;    // not 6
constexpr std::uint8_t  kWrongPLen   = 0x06;    // not 4
constexpr std::uint16_t kWrongOpcode = 0x0009;  // neither request (1) nor reply (2)

void mutateArp(std::uint8_t *f, std::uint8_t flavor) {
    switch (flavor) {
        case ut::kArpFaultHwTypeWrong:    put16(f, kArpHType, kWrongHType);   break;
        case ut::kArpFaultProtoTypeWrong: put16(f, kArpPType, kWrongPType);   break;
        case ut::kArpFaultHwLenWrong:     f[kArpHLen] = kWrongHLen;           break;
        case ut::kArpFaultProtoLenWrong:  f[kArpPLen] = kWrongPLen;           break;
        case ut::kArpFaultOpcodeWrong:    put16(f, kArpOpcode, kWrongOpcode); break;
        default:                          break;  // None / non-ARP flavor: no-op
    }
}

err_t egressFaultLinkoutput(struct netif *nif, struct pbuf *p) {
    const std::uint8_t flavor = g_egress_flavor.load(std::memory_order_relaxed);
    if (flavor != ut::kEgressFaultNone && p != nullptr && p->payload != nullptr &&
        p->len >= kArpMinLen) {
        auto *f = static_cast<std::uint8_t *>(p->payload);
        if (isArp(f)) {
            mutateArp(f, flavor);
        }
    }
    return g_orig_linkoutput(nif, p);
}

}  // namespace

void setEgressFaultFlavor(std::uint8_t flavor) {
    g_egress_flavor.store(flavor, std::memory_order_relaxed);
}

void installEgressFaultHook(struct netif *nif) {
    // Null netif, or already installed: nothing to do (idempotent — never double-wrap,
    // which would corrupt the saved original).
    if (nif == nullptr || g_orig_linkoutput != nullptr) {
        return;
    }
    g_orig_linkoutput = nif->linkoutput;
    nif->linkoutput = egressFaultLinkoutput;
}

}  // namespace tc8::lwip_dut
