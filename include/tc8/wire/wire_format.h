#pragma once

#include <cstdint>
#include <cstdio>
#include <string>

// Wire-value string formatters — the neutral-leaf home for the two generic
// address-to-text cores (docs/tech-debt.md TD-10). They render an on-wire MAC /
// IPv4 value to its canonical string and depend on nothing but the standard
// library, so they belong here in tc8::wire alongside the other wire primitives
// (readBe, ip_checksum) rather than in the Evidence-Export / verdict layer
// (sce_integration/captured_trace.h) that used to host them. With the cores here,
// presentation (cli/packet_summary.cpp, the decode-pcap exporter) and the verdict
// path both depend DOWN on this leaf, instead of the presentation side reaching UP
// into sce_integration purely for formatting.

namespace tc8::wire {

// Bare colon-separated lowercase-hex MAC string (no quotes), e.g.
// "86:e1:db:ae:77:f3". The single MAC formatter: captured_trace.h's appendMacJson
// wraps it for JSON and the documentation-site exporter (tc8-harness decode-pcap)
// reuses it for its plain-string fields, so the byte layout lives in one place.
template <typename ByteArray>
inline std::string macToHex(const ByteArray &mac) {
    char buf[18];
    std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                  static_cast<unsigned>(mac[0]), static_cast<unsigned>(mac[1]),
                  static_cast<unsigned>(mac[2]), static_cast<unsigned>(mac[3]),
                  static_cast<unsigned>(mac[4]), static_cast<unsigned>(mac[5]));
    return std::string(buf);
}

// Bare dotted-quad string (no quotes). `ip` is the uint32 with the wire's first
// octet in the low byte (LE host / NBO convention shared by the whole harness).
// The single IPv4 formatter: captured_trace.h's appendIpv4Json wraps it for JSON
// and the exporter reuses it for its plain-string fields.
inline std::string ipv4ToDotted(std::uint32_t ip) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                  static_cast<unsigned>(ip & 0xFFu),
                  static_cast<unsigned>((ip >> 8) & 0xFFu),
                  static_cast<unsigned>((ip >> 16) & 0xFFu),
                  static_cast<unsigned>((ip >> 24) & 0xFFu));
    return std::string(buf);
}

}  // namespace tc8::wire
