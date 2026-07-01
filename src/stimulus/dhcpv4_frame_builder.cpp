#include "stimulus/dhcpv4_frame_builder.h"

#include "tc8/protocol_frames/dhcpv4_frame.h"  // ::tc8::kDhcpServerPort / kDhcpClientPort (SSOT)
#include "wire/ip_checksum.h"

#include <cstring>

namespace tc8::stimulus {

namespace {

constexpr std::uint16_t kEthTypeIp4   = 0x0800;
constexpr std::size_t   kBootpFixedLen = 240;

using ::tc8::wire::inetChecksum;
using ::tc8::wire::udpChecksum;
using ::tc8::wire::writeBe16;
using ::tc8::wire::writeBe32;

}  // namespace

std::vector<std::uint8_t> buildDhcpv4Reply(const Dhcpv4ReplySpec& spec) {
    // RFC 2131 §4.3.2 DHCPNAK conformance: yiaddr MUST be 0 and the
    // message MUST NOT carry Option 51 (Lease Time) / Option 1 (Subnet
    // Mask). The builder enforces these on `message_type == 6` so
    // callers can pass a generic `ServerEmulParams` without manually
    // zeroing the irrelevant fields per call site.
    const bool is_nak = (spec.message_type == 6U);
    const std::uint32_t yiaddr_be =
        is_nak ? 0U : spec.yiaddr_be;
    const std::uint32_t lease_time_seconds =
        is_nak ? 0U : spec.lease_time_seconds;
    const std::uint32_t subnet_mask_be =
        is_nak ? 0U : spec.subnet_mask_be;

    // Compute options length up front so the IPv4 / UDP length fields
    // can be set in one pass.
    //   Option 53 (Message Type): 3 B (code + len + value)
    //   Option 54 (Server Identifier): 6 B (always emitted — every
    //              DHCP reply per RFC 2131 §4.3.1 SHOULD identify the
    //              source server)
    //   Option 51 (Lease Time): 6 B if lease_time_seconds != 0
    //   Option 1  (Subnet Mask): 6 B if subnet_mask_be != 0
    //   Option 52 (Overload): 3 B if option_52_overload != 0
    //                          (RFC 2132 §9.3, length 1)
    //   END: 1 B
    std::size_t opts_len = 3 + 6 + 1;
    if (lease_time_seconds != 0)        opts_len += 6;
    if (subnet_mask_be     != 0)        opts_len += 6;
    if (spec.option_52_overload != 0)   opts_len += 3;

    // §4.7.6.1 SUMMARY_03: pad options with 0x00 PADs so the IPv4
    // datagram reaches the requested total. Only applies when the
    // request value exceeds the natural opts length — never truncates.
    std::size_t pad_count = 0;
    if (spec.ip_datagram_total_bytes != 0) {
        const std::size_t target_ip_len = spec.ip_datagram_total_bytes;
        const std::size_t natural_ip_len = 20 + 8 + kBootpFixedLen + opts_len;
        if (target_ip_len > natural_ip_len) {
            pad_count = target_ip_len - natural_ip_len;
            opts_len += pad_count;
        }
    }

    const std::size_t udp_len   = 8 + kBootpFixedLen + opts_len;
    const std::size_t ip_len    = 20 + udp_len;
    const std::size_t frame_len = 14 + ip_len;

    std::vector<std::uint8_t> frame(frame_len, 0);
    std::uint8_t* f = frame.data();

    // Ethernet header.
    std::memcpy(f + 0, spec.eth_dst.data(), 6);
    std::memcpy(f + 6, spec.eth_src.data(), 6);
    writeBe16(f + 12, kEthTypeIp4);

    // IPv4 header.
    std::uint8_t* ip = f + 14;
    ip[0] = 0x45;  // version 4, IHL 5
    ip[1] = 0x00;  // DSCP/ECN
    writeBe16(ip + 2, static_cast<std::uint16_t>(ip_len));
    writeBe16(ip + 4, 0x0000);  // ID
    writeBe16(ip + 6, 0x0000);  // Flags + FragOff
    ip[8] = 64;    // TTL
    ip[9] = 0x11;  // proto = UDP
    writeBe16(ip + 10, 0);
    std::memcpy(ip + 12, &spec.src_ip_be, 4);
    std::memcpy(ip + 16, &spec.dst_ip_be, 4);
    writeBe16(ip + 10, inetChecksum(ip, 20));

    // UDP header.
    std::uint8_t* udp = ip + 20;
    writeBe16(udp + 0, ::tc8::kDhcpServerPort);
    writeBe16(udp + 2, ::tc8::kDhcpClientPort);
    writeBe16(udp + 4, static_cast<std::uint16_t>(udp_len));
    writeBe16(udp + 6, 0);

    // BOOTP body.
    std::uint8_t* bp = udp + 8;
    bp[0] = 2;  // BOOTREPLY
    bp[1] = 1;  // htype Ethernet
    bp[2] = 6;  // hlen
    bp[3] = 0;  // hops
    writeBe32(bp + 4, spec.xid);
    // secs (8..9) and flags (10..11) stay zero.
    // ciaddr (12..15) zero.
    std::memcpy(bp + 16, &yiaddr_be, 4);
    // siaddr (20..23) and giaddr (24..27) stay zero.
    std::memcpy(bp + 28, spec.chaddr.data(), 6);
    // sname (44..107, 64 B) and file (108..235, 128 B). Default
    // zero-init from the surrounding `frame` allocation; §4.7.6.7
    // CM_05/_06 overrides via `sname_payload` / `file_payload` so
    // RFC 2132 §9.3 Option Overload can carry a Router (Option 3 =
    // SERVER1-IP) plus an END marker through these regions.
    if (!spec.sname_payload.empty()) {
        const std::size_t copy_len =
            std::min<std::size_t>(spec.sname_payload.size(), 64);
        std::memcpy(bp + 44, spec.sname_payload.data(), copy_len);
    }
    if (!spec.file_payload.empty()) {
        const std::size_t copy_len =
            std::min<std::size_t>(spec.file_payload.size(), 128);
        std::memcpy(bp + 108, spec.file_payload.data(), copy_len);
    }
    bp[236] = 0x63;
    bp[237] = 0x82;
    bp[238] = 0x53;
    bp[239] = 0x63;

    // DHCP options.
    std::uint8_t* opts = bp + 240;
    std::size_t   o    = 0;
    opts[o++] = 53;
    opts[o++] = 1;
    opts[o++] = spec.message_type;
    opts[o++] = 54;
    opts[o++] = 4;
    std::memcpy(opts + o, &spec.server_id_be, 4);
    o += 4;
    if (lease_time_seconds != 0) {
        opts[o++] = 51;
        opts[o++] = 4;
        writeBe32(opts + o, lease_time_seconds);
        o += 4;
    }
    if (subnet_mask_be != 0) {
        opts[o++] = 1;
        opts[o++] = 4;
        std::memcpy(opts + o, &subnet_mask_be, 4);
        o += 4;
    }
    if (spec.option_52_overload != 0) {
        // RFC 2132 §9.3 Option Overload — single-byte value lives
        // alongside Option 53 and Option 54 in the main options blob;
        // the DUT-side parser keys off this option to know whether to
        // walk `sname` (bit 1, value 2) and/or `file` (bit 0, value 1)
        // for additional options.
        opts[o++] = 52;
        opts[o++] = 1;
        opts[o++] = spec.option_52_overload;
    }
    // RFC 2131 §3 PAD options (0x00) appended before END so the DHCP
    // message reaches the configured total IP datagram length. The
    // surrounding `frame` buffer was zero-initialised at allocation,
    // so the PAD bytes are already in place — only the cursor needs
    // to advance.
    o += pad_count;
    opts[o++] = 0xFF;  // END

    // UDP checksum after the body is laid out.
    writeBe16(udp + 6, udpChecksum(spec.src_ip_be, spec.dst_ip_be, udp, udp_len));

    return frame;
}

}  // namespace tc8::stimulus
