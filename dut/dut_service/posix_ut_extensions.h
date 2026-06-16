#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "dhcpv4_client.h"
#include "linklocal_autoconf.h"
#include "upper_tester/ut_server.h"

namespace tc8::dut {

// The reference (Linux) DUT's Upper Tester opcode extensions: the §4.5 IPv4
// link-local autoconfiguration family (0x0C..0x0F) and the §4.7 DHCPv4 client
// family (0x10..0x12). These depend on AF_PACKET raw injection and real
// interface state, so they are registered on the platform-agnostic UT core
// (UpperTesterServer::registerOpcode) rather than built into it — keeping
// LinklocalAutoconf / Dhcpv4Client out of the cross-platform core.
//
// Also owns the interface enumeration the core needs: the primary iface IPv4
// address (OpTriggerSendUdp's default source) and its directed broadcast
// (§4.4.4.5 ADDRESSING_02 silent discard). An instance MUST outlive the
// UpperTesterServer it registers on — the registered handlers capture its
// LinklocalAutoconf and Dhcpv4Client members.
class PosixUtExtensions {
public:
    // Enumerate non-loopback, up AF_INET interfaces (disabling TX offload so
    // CHECKSUM_03's pcap validator sees finalised checksums on veth), dedupe by
    // name, sort by name. The primary (lexicographically smallest) drives the
    // LL machine; one Dhcpv4Client is created per iface (§4.7.6.5 USAGE_01).
    void discoverInterfaces();

    // Register the 0x0C..0x12 handlers on `server`. Call before server.start().
    void registerOn(tc8::ut::UpperTesterServer &server);

    std::uint32_t ifaceIpBe() const { return iface_ip_be_; }
    std::uint32_t ifaceBcastBe() const { return iface_bcast_be_; }

private:
    std::uint32_t iface_ip_be_ = 0;
    std::uint32_t iface_bcast_be_ = 0;
    std::string iface_name_;
    std::array<std::uint8_t, 6> dut_mac_{};
    LinklocalAutoconf linklocal_autoconf_;
    std::vector<std::unique_ptr<Dhcpv4Client>> dhcpv4_clients_;
};

}  // namespace tc8::dut
