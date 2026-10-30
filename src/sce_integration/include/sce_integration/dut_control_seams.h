#pragma once

#include "sce_integration/dut_arp_control.h"
#include "sce_integration/dut_dhcp_control.h"
#include "sce_integration/dut_icmp_control.h"
#include "sce_integration/dut_linklocal_control.h"
#include "sce_integration/dut_service_primitive_control.h"
#include "sce_integration/dut_socket_config_control.h"
#include "sce_integration/dut_socket_control.h"
#include "sce_integration/dut_udp_socket_control.h"

namespace tc8::sce {

// The optional sub-interfaces of the DUT-control seam, each nullptr until a
// provider overrides it. One declaration list shared by the two kinds of provider:
// a backend (IDutControl) and a registered extension (DutControlExtension,
// dut_control_extension.h). The seams a case can reach are exactly the ones this
// list names, so a provider is written against one vocabulary and cannot offer a
// seam the cases do not know.
class IDutControlSeams {
public:
    virtual ~IDutControlSeams() = default;

    // Data-plane sub-interfaces, or nullptr when unsupported — a case checks for
    // nullptr and conditioning-skips. Default nullptr: a provider opts in by
    // overriding once it implements the sub-interface.
    virtual ITcpControl *tcpControl() { return nullptr; }
    virtual IUdpControl *udpControl() { return nullptr; }

    // TCP connection-state query — opcode, or a registered extension (no standard
    // testability SP reads a socket's state). nullptr on a backend without it; a
    // case declaring kCapTcpStateQuery is capability-skipped there (Tier 2 2b#4).
    virtual ITcpStateQuery *tcpStateQuery() { return nullptr; }

    // Kernel TCP_INFO probe — opcode-only. nullptr on a backend without it; a case
    // declaring kCapTcpInfoProbe is capability-skipped there (Tier 2 2b#4).
    virtual ITcpInfoProbe *tcpInfoProbe() { return nullptr; }

    // Out-of-band (urgent) TCP receive — opcode-only (no standard testability SP
    // reads urgent data). nullptr on a backend without it; a case declaring
    // kCapTcpRecvOob is capability-skipped there (Tier 2 2b#4).
    virtual ITcpRecvOob *tcpRecvOob() { return nullptr; }

    // DHCP client lifecycle, or nullptr when the backend cannot drive one. The
    // testability backend returns nullptr: PRS_TPSP has a DHCP group but this
    // tree has not mined its service primitives, and inventing wire primitives
    // with no spec behind them is the mistake TD-16 declined to make.
    virtual IDhcpClientControl *dhcpClientControl() { return nullptr; }

    // IPv4 link-local autoconf, or nullptr when the backend cannot start one.
    // Testability returns nullptr: PRS_TPSP names no link-local autoconf
    // primitive, and this tree does not invent wire primitives (TD-16).
    virtual ILinkLocalControl *linkLocalControl() { return nullptr; }

    // DUT UDP receive ports + receive observation, or nullptr when the provider has
    // no mapping for the question (see IUdpReceiveControl).
    virtual IUdpReceiveControl *udpReceiveControl() { return nullptr; }

    // DUT ARP-plane actions, or nullptr when the provider cannot drive them.
    virtual IArpControl *arpControl() { return nullptr; }

    // A service primitive called by group and primitive number, or nullptr when the
    // backend has no such call (the opcode UT). For primitives the DUT's owner defines
    // and this repository has no typed seam for; a case declaring kCapServicePrimitive is
    // capability-skipped on a backend that returns nullptr.
    virtual IServicePrimitiveControl *servicePrimitiveControl() { return nullptr; }

    // Socket options a case sets before the traffic it grades, or nullptr when the
    // backend has no such request (the opcode UT); a case declaring kCapSocketConfigure
    // is capability-skipped there.
    virtual ISocketConfigControl *socketConfigControl() { return nullptr; }

    // The DUT originates an ICMPv4 Echo Request, or nullptr when the backend has no such
    // request (the opcode UT); a case declaring kCapIcmpEcho is capability-skipped there.
    virtual IIcmpControl *icmpControl() { return nullptr; }

    // A UDP socket the case holds between opening and sending, or nullptr when the backend's
    // UDP is the one-shot IUdpControl send alone (the opcode UT); a case declaring
    // kCapUdpSocket is capability-skipped there.
    virtual IUdpSocketControl *udpSocketControl() { return nullptr; }
};

}  // namespace tc8::sce
