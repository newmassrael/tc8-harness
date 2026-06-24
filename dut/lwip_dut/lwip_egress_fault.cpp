// Egress field-fault injection for the lwIP fixture — the generic seam the field-
// shape `_NEG` self-validation cases drive via UT 0x18 OpSetEgressFlavor. The netif
// link-output wrapper rewrites one header field of a DUT-emitted frame, routed by
// the armed flavor; lwIP itself is untouched. Protocol-generic over one flavor
// catalog: the §4.2 ARP-over-Ethernet, §4.6.5.4 UDP, §4.8 TCP, §4.3 ICMPv4 (Echo Reply
// + Destination Unreachable), and §4.4 IPv4-header fields, each a dispatch branch on the
// same hook. A field rewrite leaves the frame's checksum mismatched — immaterial, since
// every guard reads the mutated field, not cross-field consistency (libtins delivers a
// checksum-stale frame and does not validate the IPv4 header checksum on parse). TCP
// faults are segment-selective and the ICMP/IPv4 faults are gated on the specific ICMP
// type the case observes, so each touches only the one frame the matching case observes.
#include "lwip_egress_fault.h"

#include <atomic>
#include <cstdint>

#include "lwip/err.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"

#include "tc8/upper_tester_protocol.h"

#include "lwip_wire.h"

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

// IPv4/UDP/TCP field offsets + isIpv4/l4RegionOffset/tcpHasPayload come from
// lwip_wire.h (the SSOT both fault seams read).

// Deterministic non-conformant UDP sentinels (the guard tests the field, so the
// exact wrong value is immaterial; these are unambiguous and != the spec values).
constexpr std::uint16_t kWrongPort      = 0xDEAD;  // != any per-case spec port
constexpr std::uint16_t kWrongUdpLength = 0x0007;  // < 8, never == 8 + payload

// Checksum-invalidation sentinel shared by the UDP and TCP checksum faults: XOR
// guarantees the checksum changes (a fixed value could collide with the correct one).
// The only edge — a valid 0xFFFF folding to 0x0000 — is caught by the positive
// guard's `checksum != 0` conjunct, so the _neg still passes.
constexpr std::uint16_t kChecksumFlip   = 0xFFFF;

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
                                               get16(f, udp + kUdpChecksum) ^ kChecksumFlip); break;
        default:                         break;  // None / non-UDP flavor: no-op
    }
}

// XOR sentinel for the 32-bit TCP seq/ack fields: guarantees the field changes (a
// fixed value could collide with the correct one).
constexpr std::uint32_t kTcpSeqAckFlip = 0xA5A5A5A5;

// The RFC 1122 §4.2.2.6 default MSS — the deterministic non-conformant value for the
// TCP_MSS_OPTIONS_12 fault: the case's guard forbids exactly this value, so forcing
// the advertised MSS to it is the precise violation.
constexpr std::uint16_t kRfcDefaultMss = 536;

// §4.8.6.9 MSS_OPTIONS_06/09/10 truncation: shrink a DUT data segment's IP total_length so the
// dissected TCP payload carries only 64 bytes (20 B IP + 20 B TCP + 64). libtins slices the inner
// PDU by total_length, so payload_len becomes 64 — distinct from every spec MSS (200/536/1460),
// tripping the data-segment-size guard. Mirrors kIpv4FaultTruncTotalLen for the ICMP echo case.
constexpr std::uint16_t kTcpFaultTruncTotalLen =
    static_cast<std::uint16_t>(kIpHdrLenMin + kTcpMinHdrLen + 64);

// XOR sentinel for the 16-bit ICMP echo identifier / sequence fields: guarantees the
// field changes off the echoed value (a fixed value could collide with it).
constexpr std::uint16_t kIcmpEchoFieldFlip = 0x5A5A;

// XOR sentinel for the 8-bit ICMP code field (Destination Unreachable): guarantees the
// code changes off the spec value (the guard tests code != expected, so any flip works).
constexpr std::uint8_t kIcmpCodeFlip = 0xFF;

// XOR sentinel for the first ICMP Echo Data byte. The index pattern makes data[0] == 0x00
// (byte index lo-byte), so any non-zero flip breaks payload_matches_index_pattern without
// changing the payload length. §4.4 IPv4_HEADER_05 (wrong-bytes half).
constexpr std::uint8_t kIcmpEchoDataFlip = 0xFF;

// §4.4 IPv4_HEADER_05 truncation: an Echo Reply IP total_length that carries only 64 of the
// 548 echoed Data bytes (20 B IP header + 8 B ICMP header + 64 B data). libtins slices the
// inner PDU by total_length (ip.cpp: total_sz = min(stream, tot_len - head_len)), so the
// dissected payload_len becomes 64 != 548 — the truncated-data half of the echo guard.
constexpr std::uint16_t kIpv4FaultTruncTotalLen =
    static_cast<std::uint16_t>(kIpHdrLenMin + kIcmpMinHdrLen + 64);

// §4.4 IPv4_HEADER_01: a total_length below kIpHdrLenMin (the RFC 791 20-byte
// minimum header) — defined relative to that SSOT symbol, not a bare literal.
// Non-zero so it is not read as the TCP-segmentation-offload sentinel (tot_len == 0).
constexpr std::uint16_t kIpv4FaultBadTotalLen =
    static_cast<std::uint16_t>(kIpHdrLenMin - 10);
// §4.4 IPv4_VERSION_03: the IPv4 version nibble forced to 6 (!= 4), IHL preserved.
constexpr std::uint8_t kIpv4FaultBadVersion = 6;

// TCP is stateful, so unlike ARP/UDP each fault is gated on the SPECIFIC segment the
// matching case observes — corrupting every DUT segment would break the handshake the
// observed segment depends on. The tester's guard reads the mutated field, not the
// checksum, and libpcap delivers the (now checksum-stale) segment regardless.
void mutateTcp(std::uint8_t *f, std::uint8_t flavor, std::uint16_t tcp) {
    const std::uint8_t flags = f[tcp + kTcpFlagsOff];
    const bool is_syn_ack  = (flags & kTcpFlagSyn) && (flags & kTcpFlagAck);
    const bool is_syn_only = (flags & kTcpFlagSyn) && !(flags & kTcpFlagAck);
    const bool is_rst      = (flags & kTcpFlagRst) != 0;
    // A pure ACK carries ACK with no SYN/FIN/RST and no payload — the shape of both the
    // handshake third leg and a data-elicited ACK. kTcpFaultPureAckNumWrong is armed
    // per-phase (after the handshake) so only the latter is in flight when it fires.
    const bool is_pure_ack = (flags & kTcpFlagAck) && !(flags & kTcpFlagSyn) &&
                             !(flags & kTcpFlagFin) && !is_rst && !tcpHasPayload(f, tcp);
    switch (flavor) {
        // TCP_SEQUENCE_01: flip the SYN,ACK acknowledgment so it no longer equals
        // tester_isn + 1. Flags stay SYN,ACK so the case guard still selects it.
        case ut::kTcpFaultSynAckAckWrong:
            if (is_syn_ack) put32(f, tcp + kTcpAckNumOff,
                                  get32(f, tcp + kTcpAckNumOff) ^ kTcpSeqAckFlip);
            break;
        // TCP_CHECKSUM_03 / TCP_HEADER_01: XOR-invalidate a DATA segment's checksum.
        // Gated on payload so the handshake's control segments keep valid checksums and
        // the connection still reaches ESTABLISHED to emit the observed data segment.
        case ut::kTcpFaultDataChecksumWrong:
            if (tcpHasPayload(f, tcp)) put16(f, tcp + kTcpChecksumOff,
                                             get16(f, tcp + kTcpChecksumOff) ^ kChecksumFlip);
            break;
        // TCP_BASICS_04: flip the closed-port RST's sequence off zero (RFC 793 §3.9
        // mandates SEQ=0). Gated on the RST flag so only that reset is touched.
        case ut::kTcpFaultRstSeqWrong:
            if (is_rst) put32(f, tcp + kTcpSeqNumOff,
                              get32(f, tcp + kTcpSeqNumOff) ^ kTcpSeqAckFlip);
            break;
        // TCP_HEADER_02/05/06: flip the data-elicited ACK's ack_num so it no longer
        // acknowledges the injected payload (RFC 793 §3.9). Gated on a pure ACK and
        // armed only after the handshake completes, so the handshake third leg (also a
        // pure ACK) escaped and this fires on the data-ACK the case observes.
        case ut::kTcpFaultPureAckNumWrong:
            if (is_pure_ack) put32(f, tcp + kTcpAckNumOff,
                                   get32(f, tcp + kTcpAckNumOff) ^ kTcpSeqAckFlip);
            break;
        // TCP_MSS_OPTIONS_11: zero the MSS the active-OPEN SYN advertises (a DUT that
        // omits a receive MSS). TCP_MSS_OPTIONS_12: force it to the 536 default (a DUT
        // whose MSS does not differ from the default). Both gated on the pure SYN so the
        // passive SYN,ACK of a different case is untouched; no-op if the SYN carried no
        // MSS option (tcpMssValueOffset == 0 — nothing to corrupt, fault inert).
        case ut::kTcpFaultSynMssZero:
            if (is_syn_only) {
                const std::uint16_t m = tcpMssValueOffset(f, tcp);
                if (m != 0) put16(f, m, 0);
            }
            break;
        case ut::kTcpFaultSynMssDefault:
            if (is_syn_only) {
                const std::uint16_t m = tcpMssValueOffset(f, tcp);
                if (m != 0) put16(f, m, kRfcDefaultMss);
            }
            break;
        // TCP_MSS_OPTIONS_06/09/10: shrink a DATA segment's IP total_length so libtins re-slices
        // the dissected payload to 64 B (< every spec MSS), tripping payload_len != <mss>. Gated on
        // payload so the handshake's control segments keep their length and the connection still
        // reaches the data-emitting state. The TCP header (20 B) stays within the shrunk length, so
        // libtins still dissects the segment as TCP with a 64 B payload.
        case ut::kTcpFaultDataSegTruncate:
            if (tcpHasPayload(f, tcp)) put16(f, kIpTotalLenOff, kTcpFaultTruncTotalLen);
            break;
        default: break;  // None / non-TCP flavor: no-op
    }
}

// The DUT's ICMP messages (§4.3) and the IPv4 header they ride on (§4.4). Each flavor
// is gated on the specific ICMP type the matching case observes — the Echo Reply (type
// 0) for echo id/seq + IPv4 ttl/checksum, the Destination Unreachable (type 3) for the
// code — so only that frame is touched. echo id/seq + code mutate the ICMP region;
// ttl/checksum mutate the IPv4 header (the resulting IPv4 checksum mismatch is
// immaterial: libtins does not validate the IPv4 header checksum on parse, so the guard
// still reads the field; the checksum fault invalidates that field directly).
void mutateIcmpFrame(std::uint8_t *f, std::uint8_t flavor, std::uint16_t icmp,
                     std::uint16_t avail) {
    const std::uint8_t type = f[icmp + kIcmpTypeOff];
    switch (flavor) {
        case ut::kIcmpFaultEchoIdWrong:
            if (type == kIcmpTypeEchoReply) put16(f, icmp + kIcmpEchoIdOff,
                                                  get16(f, icmp + kIcmpEchoIdOff) ^ kIcmpEchoFieldFlip);
            break;
        case ut::kIcmpFaultEchoSeqWrong:
            if (type == kIcmpTypeEchoReply) put16(f, icmp + kIcmpEchoSeqOff,
                                                  get16(f, icmp + kIcmpEchoSeqOff) ^ kIcmpEchoFieldFlip);
            break;
        case ut::kIpv4FaultTtlZero:
            if (type == kIcmpTypeEchoReply) f[kIpTtlOff] = 0;
            break;
        case ut::kIpv4FaultHdrChecksumWrong:
            if (type == kIcmpTypeEchoReply) put16(f, kIpHdrChecksumOff,
                                                  get16(f, kIpHdrChecksumOff) ^ kChecksumFlip);
            break;
        case ut::kIpv4FaultTotalLenWrong:
            // §4.4 IPv4_HEADER_01: total_length below the RFC 791 20-byte minimum.
            if (type == kIcmpTypeEchoReply) put16(f, kIpTotalLenOff, kIpv4FaultBadTotalLen);
            break;
        case ut::kIpv4FaultVersionWrong:
            // §4.4 IPv4_VERSION_03: force the version nibble to 6, preserve the IHL nibble.
            if (type == kIcmpTypeEchoReply)
                f[kIpVerIhlOff] = static_cast<std::uint8_t>(
                    (f[kIpVerIhlOff] & 0x0FU) | (kIpv4FaultBadVersion << 4));
            break;
        // TYPE_18: flip the Destination Unreachable code off the spec value (Protocol
        // Unreachable, code 2). Gated on the type-3 error message the case observes.
        case ut::kIcmpFaultDestUnreachCodeWrong:
            if (type == kIcmpTypeDestUnreach) f[icmp + kIcmpCodeOff] ^= kIcmpCodeFlip;
            break;
        // HEADER_05: corrupt the first Echo Data byte so the echoed 548 B no longer match
        // the index pattern, with the payload length untouched (the "wrong bytes" half).
        // Gated on a data byte being present in this pbuf segment (avail past the header).
        case ut::kIcmpFaultEchoPayloadByteWrong:
            if (type == kIcmpTypeEchoReply && avail > icmp + kIcmpMinHdrLen)
                f[icmp + kIcmpMinHdrLen] ^= kIcmpEchoDataFlip;
            break;
        // HEADER_05: shrink the Echo Reply's IP total_length so the dissected payload carries
        // only 64 of the 548 Data bytes (the "truncated data" half). The IP-header field at
        // kIpTotalLenOff is always present; no avail gate needed.
        case ut::kIcmpFaultEchoPayloadTruncate:
            if (type == kIcmpTypeEchoReply) put16(f, kIpTotalLenOff, kIpv4FaultTruncTotalLen);
            break;
        default: break;  // None / non-ICMP flavor: no-op
    }
}

err_t egressFaultLinkoutput(struct netif *nif, struct pbuf *p) {
    const std::uint8_t flavor = g_egress_flavor.load(std::memory_order_relaxed);
    if (flavor != ut::kEgressFaultNone && p != nullptr && p->payload != nullptr) {
        auto *f = static_cast<std::uint8_t *>(p->payload);
        if (p->len >= kArpMinLen && isArp(f)) {
            mutateArp(f, flavor);
        } else if (p->len >= kIpProtoOff + 1 && isIpv4(f) && f[kIpProtoOff] == kIpProtoUdp) {
            const std::uint16_t udp = l4RegionOffset(f);
            if (p->len >= udp + kUdpHdrLen) {
                mutateUdp(f, flavor, udp);
            }
        } else if (p->len >= kIpProtoOff + 1 && isIpv4(f) && f[kIpProtoOff] == kIpProtoTcp) {
            const std::uint16_t tcp = l4RegionOffset(f);
            if (p->len >= tcp + kTcpMinHdrLen) {
                mutateTcp(f, flavor, tcp);
            }
        } else if (p->len >= kIpProtoOff + 1 && isIpv4(f) && f[kIpProtoOff] == kIpProtoIcmp) {
            const std::uint16_t icmp = l4RegionOffset(f);
            if (p->len >= icmp + kIcmpMinHdrLen) {
                mutateIcmpFrame(f, flavor, icmp, p->len);
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
