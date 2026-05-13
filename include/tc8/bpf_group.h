#pragma once

// Protocol-scope buckets corresponding to TC8 v3.0 section chapters. Each
// registered test case declares which bucket its capture filter must cover;
// see `tc8::capture::bpf::expressionFor()` for the tcpdump-syntax dispatch.

namespace tc8 {

enum class BpfGroup {
    Arp,        // §4.2
    Icmpv4,     // §4.3
    Ipv4,       // §4.4 / §4.5
    Udp,        // §4.6
    Dhcpv4,     // §4.7
    Tcp,        // §4.8
    SomeIp,     // §5.1
    ArpAndUdp,  // §4.2 cross-protocol (ARP entry-learning cases observe
                //  both ARP presence/absence and DUT-emitted UDP frames)
    ArpAndDhcpv4, // §4.5.6.1 IPv4_AUTOCONF_INTRO_01 cross-protocol —
                  //  observe DHCPv4 lifecycle AND assert absence of ARP
                  //  Probes in 169.254/16 (RFC 3927 §1.9). Narrower than
                  //  ArpAndUdp — excludes SOME/IP SD multicast noise the
                  //  bare `udp` filter would let through.
    UdpAndDhcpv4, // §4.7.6.7 CM_05/_06 cross-protocol — observe the
                  //  DHCPv4 lifecycle (port 67/68) AND the post-BOUND
                  //  DUT-emitted UDP datagram on a non-DHCP port
                  //  destined to IP-UNUSED-ADDRESS. Excludes the SOME/IP
                  //  SD multicast UDP 30490 noise that bare `udp` would
                  //  otherwise pass on a netns shared with §5.1
                  //  emulation.
};

}  // namespace tc8
