#pragma once

// Ethernet / ARP-over-Ethernet / IPv4 / UDP / TCP wire offsets and byte helpers
// shared by the lwIP fixture's fault seams — the egress field-fault hook
// (lwip_egress_fault) and the ingress reaction-fault hook (lwip_ingress_fault).
// ARP-over-Ethernet carries no checksum and the tap/driver appends the FCS, so an
// ARP field rewrite needs no fix-up; UDP/TCP are checksum-bearing, but the seams that
// touch them either read the field (egress guards read the mutated field, not the
// checksum — libpcap delivers a bad-checksum frame) or zero the checksum to disable
// validation (ingress acceptance), so neither recomputes it here. Header-only inline
// helpers; one SSOT for the offsets every seam reads.

#include <cstdint>

namespace tc8::lwip_dut {

// Ethernet(14) + ARP field offsets within a link-output / link-input frame.
constexpr std::uint16_t kEthTypeOff  = 12;  // u16 ethertype       (0x0806 == ARP)
constexpr std::uint16_t kEthHdrLen   = kEthTypeOff + 2;  // 14 — Ethernet header (SSOT for both seams)
constexpr std::uint16_t kArpHType    = 14;  // u16 hardware type   (1 = Ethernet)
constexpr std::uint16_t kArpPType    = 16;  // u16 protocol type   (0x0800 = IPv4)
constexpr std::uint16_t kArpHLen     = 18;  // u8  hw addr length  (6)
constexpr std::uint16_t kArpPLen     = 19;  // u8  proto addr len  (4)
constexpr std::uint16_t kArpOpcode   = 20;  // u16 opcode          (1 request / 2 reply)
constexpr std::uint16_t kArpMinLen   = 22;  // bytes needed through the opcode field
constexpr std::uint16_t kArpSenderHw = 22;  // 6  sender hardware addr
constexpr std::uint16_t kArpSenderIp = 28;  // 4  sender protocol addr
constexpr std::uint16_t kArpTargetHw = 32;  // 6  target hardware addr
constexpr std::uint16_t kArpTargetIp = 38;  // 4  target protocol addr
constexpr std::uint16_t kArpFrameLen = 42;  // Ethernet(14) + ARP(28) for IPv4/Ethernet

// IPv4 / UDP / TCP field offsets. kIpProtoOff / kIpTotalLenOff are absolute from the
// frame start; the L4 field offsets are relative to the L4 region start (the IPv4 IHL
// varies, so the region offset is computed per-frame by l4RegionOffset()).
constexpr std::uint16_t kIpVerIhlOff = kEthHdrLen + 0;  // IPv4 version (hi nibble) | IHL (lo nibble)
constexpr std::uint16_t kIpTotalLenOff = kEthHdrLen + 2;  // IPv4 total length (u16)
constexpr std::uint16_t kIpTtlOff    = kEthHdrLen + 8;  // IPv4 time-to-live (u8)
constexpr std::uint16_t kIpProtoOff  = kEthHdrLen + 9;  // IPv4 protocol byte
constexpr std::uint16_t kIpHdrChecksumOff = kEthHdrLen + 10;  // IPv4 header checksum (u16)
constexpr std::uint16_t kIpSrcOff    = kEthHdrLen + 12;  // IPv4 source addr (4, network order)
constexpr std::uint16_t kIpDstOff    = kEthHdrLen + 16;  // IPv4 destination addr (4, network order)
constexpr std::uint16_t kIpHdrLenMin = 20;  // fixed IPv4 header (IHL=5, no options) — the synthesis-frame header length
constexpr std::uint8_t  kIpProtoUdp  = 17;
constexpr std::uint8_t  kIpProtoTcp  = 6;
constexpr std::uint8_t  kIpProtoIcmp = 1;
// ICMPv4 field offsets (relative to the L4 region start = Ethernet + IPv4 header).
constexpr std::uint16_t kIcmpTypeOff     = 0;   // u8 type (0 = Echo Reply, 3 = Dest Unreachable)
constexpr std::uint16_t kIcmpCodeOff     = 1;   // u8 code
constexpr std::uint16_t kIcmpChecksumOff = 2;   // u16 checksum
constexpr std::uint16_t kIcmpEchoIdOff  = 4;   // u16 identifier (Echo/Echo Reply)
constexpr std::uint16_t kIcmpEchoSeqOff = 6;   // u16 sequence number
constexpr std::uint16_t kIcmpMinHdrLen  = 8;   // bytes needed through the sequence field
constexpr std::uint8_t  kIcmpTypeEchoReply   = 0;
constexpr std::uint8_t  kIcmpTypeDestUnreach = 3;
constexpr std::uint8_t  kIcmpTypeTimeExceeded = 11;
constexpr std::uint8_t  kIcmpTypeParamProblem = 12;
constexpr std::uint8_t  kIcmpTypeInfoReply   = 16;
constexpr std::uint16_t kUdpSrcPort  = 0;
constexpr std::uint16_t kUdpDstPort  = 2;
constexpr std::uint16_t kUdpLength   = 4;
constexpr std::uint16_t kUdpChecksum = 6;
constexpr std::uint16_t kUdpHdrLen   = 8;
// TCP header field offsets (relative to the TCP region start). Only the fields the
// current §4.8 egress faults + the RST-synthesis seam read/build are defined.
constexpr std::uint16_t kTcpSrcPortOff  = 0;   // u16 source port
constexpr std::uint16_t kTcpDstPortOff  = 2;   // u16 destination port
constexpr std::uint16_t kTcpSeqNumOff   = 4;   // u32 sequence number
constexpr std::uint16_t kTcpAckNumOff   = 8;   // u32 acknowledgment number
constexpr std::uint16_t kTcpDataOffOff  = 12;  // high nibble = header length in 32-bit words
constexpr std::uint16_t kTcpFlagsOff    = 13;  // u8 control bits (… URG ACK PSH RST SYN FIN)
constexpr std::uint16_t kTcpWindowOff   = 14;  // u16 window size
constexpr std::uint16_t kTcpChecksumOff = 16;  // u16 checksum
constexpr std::uint16_t kTcpMinHdrLen   = 20;  // bytes needed through the checksum field
constexpr std::uint8_t  kTcpFlagFin     = 0x01;
constexpr std::uint8_t  kTcpFlagSyn     = 0x02;
constexpr std::uint8_t  kTcpFlagRst     = 0x04;
constexpr std::uint8_t  kTcpFlagPsh     = 0x08;
constexpr std::uint8_t  kTcpFlagAck     = 0x10;
constexpr std::uint8_t  kTcpFlagUrg     = 0x20;
// RFC 793 §3.1 kind=2 MSS option: 1 B kind + 1 B length(4) + 2 B value.
constexpr std::uint8_t  kTcpOptKindEnd  = 0;   // End of Options List (no length)
constexpr std::uint8_t  kTcpOptKindNop  = 1;   // No-Operation (no length)
constexpr std::uint8_t  kTcpOptKindMss  = 2;
constexpr std::uint8_t  kTcpOptLenMss   = 4;

inline void put16(std::uint8_t *f, std::uint16_t off, std::uint16_t v) {
    f[off] = static_cast<std::uint8_t>(v >> 8);
    f[off + 1] = static_cast<std::uint8_t>(v & 0xFF);
}

inline std::uint16_t get16(const std::uint8_t *f, std::uint16_t off) {
    return static_cast<std::uint16_t>(f[off] << 8) | f[off + 1];
}

inline void put32(std::uint8_t *f, std::uint16_t off, std::uint32_t v) {
    f[off] = static_cast<std::uint8_t>(v >> 24);
    f[off + 1] = static_cast<std::uint8_t>((v >> 16) & 0xFF);
    f[off + 2] = static_cast<std::uint8_t>((v >> 8) & 0xFF);
    f[off + 3] = static_cast<std::uint8_t>(v & 0xFF);
}

inline std::uint32_t get32(const std::uint8_t *f, std::uint16_t off) {
    return (static_cast<std::uint32_t>(f[off]) << 24) |
           (static_cast<std::uint32_t>(f[off + 1]) << 16) |
           (static_cast<std::uint32_t>(f[off + 2]) << 8) |
           static_cast<std::uint32_t>(f[off + 3]);
}

inline bool isArp(const std::uint8_t *f) {
    return f[kEthTypeOff] == 0x08 && f[kEthTypeOff + 1] == 0x06;
}

inline bool isIpv4(const std::uint8_t *f) {
    return f[kEthTypeOff] == 0x08 && f[kEthTypeOff + 1] == 0x00;
}

// Byte offset of the L4 region (UDP or TCP) within an Ethernet+IPv4 frame: Ethernet
// header + the IPv4 header whose length the IHL nibble carries (so an options-bearing
// header still lands the L4 offset correctly). Protocol-agnostic.
inline std::uint16_t l4RegionOffset(const std::uint8_t *f) {
    return static_cast<std::uint16_t>(kEthHdrLen + (f[kEthHdrLen] & 0x0F) * 4);
}

// True if the IPv4+TCP frame carries TCP payload (IP total length exceeds the IPv4
// header + the TCP header the data-offset nibble declares). Lets a TCP egress fault
// target only data segments and leave the handshake's control segments intact.
inline bool tcpHasPayload(const std::uint8_t *f, std::uint16_t tcp) {
    const std::uint16_t ip_total = get16(f, kIpTotalLenOff);
    const std::uint16_t ip_hdr   = static_cast<std::uint16_t>((f[kEthHdrLen] & 0x0F) * 4);
    const std::uint16_t tcp_hdr  = static_cast<std::uint16_t>((f[tcp + kTcpDataOffOff] >> 4) * 4);
    return ip_total > static_cast<std::uint16_t>(ip_hdr + tcp_hdr);
}

// Byte offset of the 2-byte MSS option value within an Ethernet+IPv4+TCP frame, or 0
// if the segment carries no RFC 793 §3.1 kind=2 MSS option. Walks the TCP option TLV
// chain between the 20-byte fixed header and the data-offset-declared header end
// (kind 0 = End-of-Options, kind 1 = NOP single byte, others length-prefixed). Lets a
// SYN MSS fault rewrite the advertised MSS wherever the stack placed the option,
// independent of option ordering. Stops on any truncated/malformed option.
inline std::uint16_t tcpMssValueOffset(const std::uint8_t *f, std::uint16_t tcp) {
    const std::uint16_t opt_start = static_cast<std::uint16_t>(tcp + kTcpMinHdrLen);
    const std::uint16_t opt_end =
        static_cast<std::uint16_t>(tcp + (f[tcp + kTcpDataOffOff] >> 4) * 4);
    std::uint16_t i = opt_start;
    while (i < opt_end) {
        const std::uint8_t kind = f[i];
        if (kind == kTcpOptKindEnd) break;
        if (kind == kTcpOptKindNop) { i++; continue; }
        if (i + 1 >= opt_end) break;  // truncated length-prefixed option
        const std::uint8_t len = f[i + 1];
        if (len < 2 || i + len > opt_end) break;  // malformed length
        if (kind == kTcpOptKindMss && len == kTcpOptLenMss) {
            return static_cast<std::uint16_t>(i + 2);
        }
        i = static_cast<std::uint16_t>(i + len);
    }
    return 0;
}

}  // namespace tc8::lwip_dut
