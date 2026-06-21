// Egress field-fault injection for the lwIP fixture — the generic seam the field-
// shape `_NEG` self-validation cases drive via UT 0x18 OpSetEgressFlavor. The netif
// link-output wrapper rewrites one header field of a DUT-emitted frame (and
// recomputes the affected checksum), routed by the armed flavor; lwIP itself is
// untouched. Protocol-generic over one flavor catalog: the §4.2 ARP-over-Ethernet
// fields and the §4.6.5.4 UDP fields today, with TCP/IPv4/ICMP joining the same
// hook. A field rewrite leaves the frame's checksum mismatched — immaterial, since
// every guard reads the mutated field, not cross-field consistency.
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

// IPv4/UDP field offsets (Ethernet(14) + IPv4 header; the IPv4 IHL is read so an
// options-bearing header still lands the UDP offset correctly). UDP offsets are
// relative to the UDP start.
constexpr std::uint16_t kEthHdrLen   = 14;
constexpr std::uint16_t kIpProtoOff  = kEthHdrLen + 9;   // IPv4 protocol byte
constexpr std::uint8_t  kIpProtoUdp  = 17;
constexpr std::uint16_t kUdpSrcPort  = 0;
constexpr std::uint16_t kUdpDstPort  = 2;
constexpr std::uint16_t kUdpLength   = 4;
constexpr std::uint16_t kUdpChecksum = 6;
constexpr std::uint16_t kUdpHdrLen   = 8;

// Deterministic non-conformant UDP sentinels (the guard tests the field, so the
// exact wrong value is immaterial; these are unambiguous and != the spec values).
constexpr std::uint16_t kWrongPort      = 0xDEAD;  // != any per-case spec port
constexpr std::uint16_t kWrongUdpLength = 0x0007;  // < 8, never == 8 + payload

bool isIpv4(const std::uint8_t *f) {
    return f[kEthTypeOff] == 0x08 && f[kEthTypeOff + 1] == 0x00;
}

void mutateUdp(std::uint8_t *f, std::uint8_t flavor, std::uint16_t udp) {
    // Never the DUT's own UT Confirmation (src_port == ut::kPort) — only its
    // spec-provoked data egress carries a per-case source port.
    if (get16(f, udp + kUdpSrcPort) == ut::kPort) {
        return;
    }
    // Each flavor rewrites ONE UDP field. The resulting checksum mismatch is
    // immaterial: every §4.6.5.4 `_neg` guard reads the mutated field, not
    // cross-field consistency, and the tester's dissector parses the UDP header
    // regardless of the checksum (no drop). The checksum flavor invalidates the
    // checksum field directly. (A faithful valid-checksum recompute is deferred —
    // not needed by any guard here.)
    switch (flavor) {
        case ut::kUdpFaultSrcPortWrong:  put16(f, udp + kUdpSrcPort, kWrongPort);     break;
        case ut::kUdpFaultDstPortWrong:  put16(f, udp + kUdpDstPort, kWrongPort);     break;
        case ut::kUdpFaultLengthWrong:   put16(f, udp + kUdpLength, kWrongUdpLength); break;
        case ut::kUdpFaultChecksumWrong: put16(f, udp + kUdpChecksum,
                                               get16(f, udp + kUdpChecksum) ^ 0xFFFF); break;
        default:                         break;  // None / non-UDP flavor: no-op
    }
}

err_t egressFaultLinkoutput(struct netif *nif, struct pbuf *p) {
    const std::uint8_t flavor = g_egress_flavor.load(std::memory_order_relaxed);
    if (flavor != ut::kEgressFaultNone && p != nullptr && p->payload != nullptr) {
        auto *f = static_cast<std::uint8_t *>(p->payload);
        if (p->len >= kArpMinLen && isArp(f)) {
            mutateArp(f, flavor);
        } else if (p->len >= kIpProtoOff + 1 && isIpv4(f) && f[kIpProtoOff] == kIpProtoUdp) {
            const std::uint16_t udp = kEthHdrLen + (f[kEthHdrLen] & 0x0F) * 4;
            if (p->len >= udp + kUdpHdrLen) {
                mutateUdp(f, flavor, udp);
            }
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
