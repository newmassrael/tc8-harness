#pragma once

#include <array>
#include <cstdint>
#include <cstdio>
#include <string>

#include "tc8/protocol_frames/ipv4_frame.h"

#include "wire/ip_checksum.h"  // tc8::wire::inetChecksum (RFC 1071 SSOT)

#include "sce_integration/captured_frame_timing.h"
#include "sce_integration/captured_trace.h"
#include "test_config.h"

namespace tc8 {

// SCE Named Context struct carrying fields parsed from an observed IPv4
// header. Matching SCXML declaration:
//   <sce:context id="captured" cpp:type="tc8::Ipv4Captured"
//                cpp:include="sce_integration/ipv4_captured.h"/>
//
// Mirror of `tc8::Ipv4Frame` (RFC 791): version/IHL/TOS/total_length/
// identification/flags/fragment_offset/TTL/protocol/header_checksum plus
// src/dst addresses in network byte order (same convention as
// `Icmpv4Captured::src_ip` / `dst_ip` so cases comparing against
// `cfg.ipv4.dut_iface_ip` do not need to byte-swap).
//
// Options region is intentionally not mirrored in the §4.4 HEADER /
// CHECKSUM / TTL / VERSION pilot — libtins parses IP options into a
// vector of `IP::option`, not a raw byte range. §4.4 has no OPTIONS
// subsection in TC8 v3.0 (IPv4_OPTIONS_01..14 deleted V2→V3). If an
// ICMPv4 consumer that carries IP options in the stimulus ever needs
// byte-level observation (e.g. ICMPv4_TYPE_05 / ERROR_02/03/04 — all
// stimulate with an Internet Timestamp option), a serialisation helper
// should be added rather than caching stale pointers here.
// `Ipv4Frame::options_data` / `options_len` are left untouched for that
// future expansion.
struct Ipv4Captured : CapturedFrameTiming {
    std::uint8_t  version         = 0;
    std::uint8_t  ihl             = 0;   // header length in 32-bit words
    std::uint8_t  tos             = 0;
    std::uint16_t total_length    = 0;
    std::uint16_t identification  = 0;
    std::uint8_t  flags           = 0;   // 3-bit: Reserved / DF / MF
    std::uint16_t fragment_offset = 0;   // 13-bit
    std::uint8_t  ttl             = 0;
    std::uint8_t  protocol        = 0;
    std::uint16_t header_checksum = 0;
    std::uint32_t src_addr        = 0;   // network byte order
    std::uint32_t dst_addr        = 0;   // network byte order

    // §4.4.4.2 IPv4_CHECKSUM_05: "DUT uses the checksum calculation
    // method according to RFC." Reconstruct a 20-byte IPv4 header from
    // the captured scalar fields (including the checksum field in its
    // wire position) and verify the RFC 1071 one's-complement sum is
    // zero. Exposed as a member method so SCE's `captured.` → `this->
    // captured_->` codegen rewrite covers the call — the ICMPv4_TYPE_08
    // precedent is `payload_equals` on `Icmpv4Captured`.
    //
    // The RFC 1071 fold routes through the tc8::wire SSOT shared with every
    // builder; only the cross-language Python mirror in site/scripts/decode_pcap.py
    // (`ip_header_checksum_ok`) stays a hand-copy, which no C++ SSOT can subsume.
    // See docs/tech-debt.md TD-04.
    //
    // Limited to the IHL=5 (no-options) case: every DUT Echo Reply the
    // pilot observes has the kernel's default no-options header, so
    // options reconstruction would be dead weight here. IPv4_OPTIONS_*
    // are v3.0-deleted, so the only realistic future IHL>5 observer is
    // an ICMPv4 case where the DUT echoes an options header back (see
    // ICMPv4_TYPE_05 stimulus shape) — extend via raw-bytes snapshot in
    // `Ipv4Frame` if such a case lands.
    bool header_checksum_valid() const {
        if (ihl != 5U) return false;
        std::array<std::uint8_t, 20> hdr{};
        hdr[0]  = static_cast<std::uint8_t>(((version & 0x0FU) << 4) | (ihl & 0x0FU));
        hdr[1]  = tos;
        hdr[2]  = static_cast<std::uint8_t>((total_length >> 8) & 0xFFU);
        hdr[3]  = static_cast<std::uint8_t>(total_length & 0xFFU);
        hdr[4]  = static_cast<std::uint8_t>((identification >> 8) & 0xFFU);
        hdr[5]  = static_cast<std::uint8_t>(identification & 0xFFU);
        hdr[6]  = static_cast<std::uint8_t>(((flags & 0x07U) << 5)
                     | ((fragment_offset >> 8) & 0x1FU));
        hdr[7]  = static_cast<std::uint8_t>(fragment_offset & 0xFFU);
        hdr[8]  = ttl;
        hdr[9]  = protocol;
        hdr[10] = static_cast<std::uint8_t>((header_checksum >> 8) & 0xFFU);
        hdr[11] = static_cast<std::uint8_t>(header_checksum & 0xFFU);
        // src/dst already in NBO; little-endian host stores bytes 0..3
        // of `src_addr` as AC.10.00.XX for 172.16.0.XX.
        hdr[12] = static_cast<std::uint8_t>((src_addr >> 0)  & 0xFFU);
        hdr[13] = static_cast<std::uint8_t>((src_addr >> 8)  & 0xFFU);
        hdr[14] = static_cast<std::uint8_t>((src_addr >> 16) & 0xFFU);
        hdr[15] = static_cast<std::uint8_t>((src_addr >> 24) & 0xFFU);
        hdr[16] = static_cast<std::uint8_t>((dst_addr >> 0)  & 0xFFU);
        hdr[17] = static_cast<std::uint8_t>((dst_addr >> 8)  & 0xFFU);
        hdr[18] = static_cast<std::uint8_t>((dst_addr >> 16) & 0xFFU);
        hdr[19] = static_cast<std::uint8_t>((dst_addr >> 24) & 0xFFU);

        // inetChecksum folds the same RFC 1071 sum the builders use
        // (writeBe16(ip+10, inetChecksum(ip, 20))) and returns its complement;
        // summed over the header WITH its checksum field in place, a correct field
        // makes the fold 0xFFFF, so the complement is 0.
        return ::tc8::wire::inetChecksum(hdr.data(), hdr.size()) == 0U;
    }

    // Inter-frame timing surface (`observed_ts_us` / `prev_observed_ts_us`
    // / `frame_delta_us()`) is inherited from `CapturedFrameTiming`. IPv4
    // cases dispatch via `dispatchIpv4Frame`, which auto-snapshots prev on
    // fired-transition frames; first-transition guards must NOT depend on
    // `frame_delta_us()`. §4.4.4.7 REASSEMBLY-style inter-fragment timing
    // cases (when they land) read it to verify reassembly-timer behaviour.
};

// ADL hook called by `TestRunner<SM>` at construction. No-op for captured
// because captured fields get populated from wire frames, not from CLI
// configuration; the overload exists so the uniform
// `applyTestConfig(c, cfg)` call in TestRunner compiles for every Named
// Context type.
inline void applyTestConfig(Ipv4Captured & /*c*/, const TestConfig & /*cfg*/) {
    // captured-from-wire fields have no CLI-driven initial values.
}

inline void fillIpv4CapturedFromFrame(Ipv4Captured &c, const Ipv4Frame &f) {
    c.version         = f.version;
    c.ihl             = f.ihl;
    c.tos             = f.tos;
    c.total_length    = f.total_length;
    c.identification  = f.identification;
    c.flags           = f.flags;
    c.fragment_offset = f.fragment_offset;
    c.ttl             = f.ttl;
    c.protocol        = f.protocol;
    c.header_checksum = f.header_checksum;
    c.src_addr        = f.src_addr;
    c.dst_addr        = f.dst_addr;
    c.observed_ts_us  = f.observed_ts_us;
}

// Trace-recording hook (Evidence Export). See arp_captured.h for the
// design overview; this overload exposes the IPv4 header subset most
// SCXML conds gate on (version/ihl/ttl + 3-tuple + total_length).
inline void appendCapturedJson(std::string &out, const Ipv4Captured &c) {
    out.append("{");
    ::tc8::sce::appendUintJson(out, "\"version\":", c.version);
    ::tc8::sce::appendUintJson(out, ",\"ihl\":", c.ihl);
    ::tc8::sce::appendUintJson(out, ",\"ttl\":", c.ttl);
    ::tc8::sce::appendUintJson(out, ",\"protocol\":", c.protocol);
    ::tc8::sce::appendUintJson(out, ",\"total_length\":", c.total_length);
    ::tc8::sce::appendUintJson(out, ",\"identification\":", c.identification);
    ::tc8::sce::appendUintJson(out, ",\"flags\":", c.flags);
    ::tc8::sce::appendUintJson(out, ",\"fragment_offset\":", c.fragment_offset);
    out.append(",\"src_addr\":");
    ::tc8::sce::appendIpv4Json(out, c.src_addr);
    out.append(",\"dst_addr\":");
    ::tc8::sce::appendIpv4Json(out, c.dst_addr);
    ::tc8::sce::appendTimingJson(out, c);
    out.append("}");
}

}  // namespace tc8
