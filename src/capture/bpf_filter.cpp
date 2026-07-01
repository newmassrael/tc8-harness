#include "capture/bpf_filter.h"

#include <arpa/inet.h>
#include <netinet/in.h>

#include <optional>
#include <string>
#include <string_view>

#include "sce_integration/dhcpv4_default_endpoints.h"
#include "tc8/dut_config.h"
#include "tc8/protocol_frames/dhcpv4_frame.h"  // ::tc8::kDhcpServerPort / kDhcpClientPort (SSOT)
#include "tc8/upper_tester_protocol.h"

namespace tc8::capture::bpf {

std::string arp() {
    return "arp";
}

std::string icmpv4() {
    return "icmp";
}

std::string ipv4() {
    // Generic IPv4 capture (all transports). Not currently wired by any
    // case — §4.4 ICMP-stimulus cases (HEADER/CHECKSUM/TTL/VERSION/
    // ADDRESSING_03) use `BpfGroup::Icmpv4` instead because the DUT's
    // SOME/IP SD UDP multicast (src=DUT) would otherwise spuriously
    // trigger SCXML guards keyed on src_addr. Future UDP-stimulus cases
    // (§4.4.4.5 ADDRESSING_01/_02) will likely route through a narrower
    // group too, but the literal "ip" stays reserved for a hypothetical
    // cross-transport case that legitimately needs to observe every IP
    // packet. ARP traffic stays on `BpfGroup::Arp` / `ArpAndUdp`.
    return "ip";
}

std::string udp() {
    return "udp";
}

std::string tcp() {
    // §4.8 BASICS / CALL_RECEIVE / CLOSING / FLAGS_PROCESSING /
    // MSS_OPTIONS / RETRANSMISSION_TO / URGENT_PTR — many cases drive
    // the DUT through the §4.8.5 Upper Tester (UDP kPort=30600), and a
    // few read kernel state back via OpQueryTcpInfo (0x13). The UT
    // request/response itself never carries verdict-bearing TCP
    // segments, but the on-disk pcap loses observability of the
    // stimulus envelope without it — `tc8-harness decode-pcap` decodes
    // the UDP UT frames into the site timeline (summarising opcode +
    // status). Widening the kernel BPF here is verdict-neutral
    // because dispatchTcpFrame() pattern-matches on TcpFrame via
    // std::get_if and silently ignores UdpFrame events.
    return "tcp or (udp and port " + std::to_string(tc8::ut::kPort) + ")";
}

std::string dhcpv4() {
    return "udp and (port " + std::to_string(::tc8::kDhcpServerPort) + " or port " +
           std::to_string(::tc8::kDhcpClientPort) + ")";
}

std::string portRange(std::uint16_t lo, std::uint16_t hi) {
    const std::string range = std::to_string(lo) + "-" + std::to_string(hi);
    return "udp portrange " + range + " or tcp portrange " + range;
}

std::string udpPorts(const std::uint16_t *ports, std::size_t count) {
    std::string expr;
    for (std::size_t i = 0; i < count; ++i) {
        if (!expr.empty()) {
            expr += " or ";
        }
        expr += "udp port " + std::to_string(ports[i]);
    }
    return expr;
}

std::string someip() {
    return portRange(tc8::dut::kCapturePortLow, tc8::dut::kCapturePortHigh);
}

std::string arpAndUdp() {
    return "arp or udp";
}

std::string arpAndDhcpv4() {
    // §4.5.6.1 IPv4_AUTOCONF_INTRO_01: observe BOTH ARP frames (assert
    // absence of post-bind LL probe) AND the DHCPv4 lifecycle. Narrower
    // than `arpAndUdp` — bare `udp` would also match SOME/IP SD multicast
    // (UDP 30490) which adds spurious capture noise on netns shared with
    // the §5.1 service emulation. Pinning to ports 67/68 keeps the
    // BPF-level filter clean.
    return "arp or (udp and (port " + std::to_string(::tc8::kDhcpServerPort) + " or port " +
           std::to_string(::tc8::kDhcpClientPort) + "))";
}

std::string udpAndDhcpv4() {
    // §4.7.6.7 CM_05/_06: observe BOTH the DHCPv4 lifecycle AND the
    // post-BOUND DUT-emitted UDP datagram on a non-DHCP data port.
    // Excludes SOME/IP SD multicast (port 30490) and the wider 30490-
    // 30510 service window so the harness sees only DHCP + the
    // tester's UT-driven egress (default kDataPort = 20000) plus the
    // expected DUT egress to `kUnusedRoutedIpBe`. The dst-address
    // half makes the filter robust even if the DUT picks an
    // ephemeral src_port — the destination is `kUnusedRoutedIpBe`
    // and there is no other traffic on the testbed toward that IP.
    //
    // Address dotted-string is rendered from the same constexpr SSOT
    // (`kUnusedRoutedIpBe`) the SCXML cond reads — no parallel
    // literal can drift out of sync.
    char unused_ip[INET_ADDRSTRLEN] = {};
    const in_addr unused_addr{::tc8::sce::dhcpv4::kUnusedRoutedIpBe};
    ::inet_ntop(AF_INET, &unused_addr, unused_ip, sizeof(unused_ip));
    return "udp and (port " + std::to_string(::tc8::kDhcpServerPort) + " or port "
           + std::to_string(::tc8::kDhcpClientPort) + " or port "
           + std::to_string(tc8::ut::kDataPort)
           + " or host " + unused_ip + ")";
}

std::string vlanAware(const std::string &expr) {
    return "(" + expr + ") or (vlan and (" + expr + "))";
}

std::string resolveCaptureFilter(const std::optional<std::string> &cli_override,
                                 std::string_view per_case_expression,
                                 ::tc8::BpfGroup group,
                                 const std::uint16_t *extra_udp_ports,
                                 std::size_t extra_udp_port_count) {
    if (cli_override.has_value()) {
        return *cli_override;
    }
    if (!per_case_expression.empty()) {
        return std::string(per_case_expression);
    }
    const std::string extra = udpPorts(extra_udp_ports, extra_udp_port_count);
    if (extra.empty()) {
        return expressionFor(group);
    }
    // Union the case's extra UDP ports with the group's BARE expression, then
    // wrap the whole union in vlanAware() ONCE. Wrapping each half separately
    // and OR-ing the two independently VLAN-aware halves (the previous shape)
    // put two `vlan` keywords in the filter; libpcap's first `vlan` shifts the
    // decode offset for the REMAINDER of the expression (libpcap-filter(7)), so
    // the trailing half's untagged arm was compiled at the VLAN offset and
    // silently matched only tagged frames. One trailing `vlan` over the full
    // union keeps every untagged port term at offset 0 while still matching a
    // single 802.1Q tag.
    return vlanAware("(" + bareExpressionFor(group) + ") or (" + extra + ")");
}

std::string bareExpressionFor(::tc8::BpfGroup group) {
    // Exhaustive switch. A new BpfGroup alternative must add a case
    // here; -Wswitch flags the omission, and __builtin_unreachable()
    // on the fall-through path keeps us from silently defaulting to
    // someip() (a prior bug before this was locked down).
    switch (group) {
    case ::tc8::BpfGroup::Arp:
        return arp();
    case ::tc8::BpfGroup::Icmpv4:
        return icmpv4();
    case ::tc8::BpfGroup::Ipv4:
        return ipv4();
    case ::tc8::BpfGroup::Udp:
        return udp();
    case ::tc8::BpfGroup::Dhcpv4:
        return dhcpv4();
    case ::tc8::BpfGroup::Tcp:
        return tcp();
    case ::tc8::BpfGroup::SomeIp:
        return someip();
    case ::tc8::BpfGroup::ArpAndUdp:
        return arpAndUdp();
    case ::tc8::BpfGroup::ArpAndDhcpv4:
        return arpAndDhcpv4();
    case ::tc8::BpfGroup::UdpAndDhcpv4:
        return udpAndDhcpv4();
    }
    __builtin_unreachable();
}

std::string expressionFor(::tc8::BpfGroup group) {
    // Wrap the group's bare expression in vlanAware() exactly once here so a
    // tagged frame is never silently dropped, and a future BpfGroup cannot
    // forget to opt in. resolveCaptureFilter() reuses bareExpressionFor()
    // directly when it needs to union extra ports before the single wrap.
    return vlanAware(bareExpressionFor(group));
}

}  // namespace tc8::capture::bpf
