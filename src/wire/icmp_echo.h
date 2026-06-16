#pragma once

#include <cstdint>
#include <optional>
#include <vector>

namespace tc8::wire {

// RFC 792 ICMP Echo Request body: the 8-byte ICMP header (type, code, checksum,
// identifier, sequence number) followed by `data`, carrying a valid RFC 1071
// checksum (tc8::wire::inetChecksum) computed over the whole body.
//
// `type` / `code` default to Echo Request (8 / 0); the overrides build the
// structurally identical Information Request (15/0), Destination Unreachable
// (3/2) etc. — the 8-byte header layout (identifier + sequence in the
// rest-of-header slots) is shared across these types. `corrupt_checksum` flips
// one checksum bit after the compute pass, used by TYPE_10's malformed Echo
// Request to make the DUT's kernel reject the frame.
//
// Body-only granularity (no IP/Ethernet wrapping) lets the FRAGMENTS cases split
// one body across fragments — a single checksum covers the full reassembled
// payload the DUT sees — and lets the testability UTM emit a bare Echo Request
// over an ICMP socket. Living in the wire layer, it is the one source both the
// tester-side stimulus builders and the DUT-side testability endpoint frame
// echoes from, so the emitted and observed bytes agree by construction.
std::vector<std::uint8_t> buildIcmpEchoRequestBody(
    std::uint16_t id,
    std::uint16_t seq,
    const std::uint8_t *data,
    std::uint32_t data_len,
    std::optional<std::uint8_t> type_override = std::nullopt,
    std::optional<std::uint8_t> code_override = std::nullopt,
    bool corrupt_checksum = false);

// RFC 4443 ICMPv6 Echo Request body: the 8-byte ICMPv6 header (type 128, code 0,
// checksum, identifier, sequence number) followed by `data`. Unlike the IPv4
// builder above it leaves the checksum field zero — the ICMPv6 checksum spans an
// IPv6 pseudo-header (src / dst / length / next-header) the body builder cannot
// know, and the kernel computes and inserts it for every IPPROTO_ICMPV6 socket
// (RFC 3542 §3.1), so a body-local checksum would only be overwritten. The
// header layout is shared with the IPv4 echo, so a DUT testability endpoint
// frames both from this one wire layer.
std::vector<std::uint8_t> buildIcmpv6EchoRequestBody(std::uint16_t id, std::uint16_t seq,
                                                     const std::uint8_t *data,
                                                     std::uint32_t data_len);

}  // namespace tc8::wire
