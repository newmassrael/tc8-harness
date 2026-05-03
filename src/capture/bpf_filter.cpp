#include "capture/bpf_filter.h"

#include <arpa/inet.h>
#include <netinet/in.h>

#include <string>

#include "sce_integration/dhcpv4_default_endpoints.h"
#include "tc8/dut_config.h"
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
    return "tcp";
}

std::string dhcpv4() {
    return "udp and (port 67 or port 68)";
}

std::string portRange(std::uint16_t lo, std::uint16_t hi) {
    const std::string range = std::to_string(lo) + "-" + std::to_string(hi);
    return "udp portrange " + range + " or tcp portrange " + range;
}

std::string someip() {
    return portRange(tc8::dut::kCapturePortLow, tc8::dut::kCapturePortHigh);
}

std::string arpAndUdp() {
    return "arp or udp";
}

std::string arpAndDhcpv4() {
    // §4.5.6.1 IPV4_AUTOCONF_INTRO_01: observe BOTH ARP frames (assert
    // absence of post-bind LL probe) AND the DHCPv4 lifecycle. Narrower
    // than `arpAndUdp` — bare `udp` would also match SOME/IP SD multicast
    // (UDP 30490) which adds spurious capture noise on netns shared with
    // the §5.1 service emulation. Pinning to ports 67/68 keeps the
    // BPF-level filter clean.
    return "arp or (udp and (port 67 or port 68))";
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
    return "udp and (port 67 or port 68 or port "
           + std::to_string(tc8::ut::kDataPort)
           + " or host " + unused_ip + ")";
}

std::string expressionFor(::tc8::BpfGroup group) {
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

}  // namespace tc8::capture::bpf
