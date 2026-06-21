#pragma once

// Ethernet / ARP-over-Ethernet / IPv4 / UDP wire offsets and byte helpers shared by
// the lwIP fixture's fault seams — the egress field-fault hook (lwip_egress_fault)
// and the ingress reaction-fault hook (lwip_ingress_fault). ARP-over-Ethernet
// carries no checksum and the tap/driver appends the FCS, so an ARP field rewrite
// needs no fix-up; UDP is checksum-bearing, but the seams that touch it either read
// the field (egress guards) or zero the checksum to disable validation (ingress
// acceptance), so neither recomputes it here. Header-only inline helpers; one SSOT
// for the offsets every seam reads.

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

// IPv4 / UDP field offsets. kIpProtoOff is absolute from the frame start; the UDP
// field offsets are relative to the UDP region start (the IPv4 IHL varies, so the
// UDP region offset is computed per-frame by udpRegionOffset()).
constexpr std::uint16_t kIpProtoOff  = kEthHdrLen + 9;  // IPv4 protocol byte
constexpr std::uint8_t  kIpProtoUdp  = 17;
constexpr std::uint16_t kUdpSrcPort  = 0;
constexpr std::uint16_t kUdpDstPort  = 2;
constexpr std::uint16_t kUdpLength   = 4;
constexpr std::uint16_t kUdpChecksum = 6;
constexpr std::uint16_t kUdpHdrLen   = 8;

inline void put16(std::uint8_t *f, std::uint16_t off, std::uint16_t v) {
    f[off] = static_cast<std::uint8_t>(v >> 8);
    f[off + 1] = static_cast<std::uint8_t>(v & 0xFF);
}

inline std::uint16_t get16(const std::uint8_t *f, std::uint16_t off) {
    return static_cast<std::uint16_t>(f[off] << 8) | f[off + 1];
}

inline bool isArp(const std::uint8_t *f) {
    return f[kEthTypeOff] == 0x08 && f[kEthTypeOff + 1] == 0x06;
}

inline bool isIpv4(const std::uint8_t *f) {
    return f[kEthTypeOff] == 0x08 && f[kEthTypeOff + 1] == 0x00;
}

// Byte offset of the UDP region within an Ethernet+IPv4 frame: Ethernet header +
// the IPv4 header whose length the IHL nibble carries (so an options-bearing header
// still lands the UDP offset correctly).
inline std::uint16_t udpRegionOffset(const std::uint8_t *f) {
    return static_cast<std::uint16_t>(kEthHdrLen + (f[kEthHdrLen] & 0x0F) * 4);
}

}  // namespace tc8::lwip_dut
