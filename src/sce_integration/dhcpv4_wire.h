#pragma once

#include <algorithm>
#include <cstdint>
#include <cstring>

#include "tc8/protocol_frames/dhcpv4_frame.h"

#include "sce_integration/wire_read.h"

// Authoritative C++ consumer of the DHCPv4 BOOTP fixed-header wire-layout
// SSOT in dhcpv4_wire.def. The byte offsets are owned by the .def and
// expanded here, so this decoder cannot drift from it; the Python site
// mirror (site/scripts/dhcpv4_wire_generated.py) is generated from the same
// .def. See docs/tech-debt.md TD-02.
namespace tc8::dhcpv4_wire {

// Named offsets/constants owned by the .def (TC8_DHCP_CONST rows).
#define TC8_DHCP_CONST(name, value) inline constexpr std::uint32_t name = (value);
#include "dhcpv4_wire.def"
#undef TC8_DHCP_CONST

// Decode the RFC 951 / RFC 2131 BOOTP fixed header (op..chaddr) from `bp`
// into `df`. Caller guarantees at least kOptionsOff (240) bytes. The
// L2/L3/L4 envelope fields (eth_*, src_ip, dst_*, ports) are filled by the
// caller from the carrying UDP frame, and the post-cookie options TLV chain
// has no fixed offsets, so its walk stays in the caller — both are outside
// this offset SSOT by design.
inline void decodeBootpFixedHeader(const std::uint8_t *bp, Dhcpv4Frame &df) {
#define TC8_DHCP_FIELD(member, off, size)        \
    df.member = static_cast<decltype(df.member)>( \
        ::tc8::wire::readBe(bp + (off), (size), 0, 0xFFFFFFFFu));
#define TC8_DHCP_ADDR(member, off) std::memcpy(&df.member, bp + (off), 4);
#define TC8_DHCP_BYTES(member, off, len) \
    std::copy(bp + (off), bp + (off) + (len), df.member.begin());
#include "dhcpv4_wire.def"
#undef TC8_DHCP_FIELD
#undef TC8_DHCP_ADDR
#undef TC8_DHCP_BYTES
}

// True iff the 4 bytes at kMagicCookieOff equal the RFC 1497 / RFC 2131
// magic cookie. Caller guarantees at least kOptionsOff bytes.
inline bool magicCookieValid(const std::uint8_t *bp) {
    return ::tc8::wire::readBe(bp + kMagicCookieOff, 4, 0, 0xFFFFFFFFu) == kMagicCookie;
}

}  // namespace tc8::dhcpv4_wire
