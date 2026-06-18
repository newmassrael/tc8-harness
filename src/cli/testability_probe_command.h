#pragma once

#include <string>

#include <CLI/CLI.hpp>

namespace tc8::cli {

// `tc8-harness testability-probe` — exercises a DUT's AUTOSAR Testability
// Protocol endpoint (PRS Testability TC 1.2.0) end to end: GET_VERSION +
// START_TEST + a UDP CREATE_AND_BIND / SEND_DATA / CLOSE_SOCKET data-plane
// loop + (with --tcp-data) a TCP CREATE_AND_BIND / CONNECT / SEND_DATA /
// CLOSE_SOCKET active-open loop + (with --icmp) an ICMP ECHO_REQUEST loop +
// (with --eth) an ETH INTERFACE_DOWN/UP loop that OBSERVES the link toggle by
// watching reachability on a second interface + END_TEST, reporting each Result
// ID. The standard-protocol counterpart to `ut-ping` (which speaks the in-house
// opcode UT). Exit 0 when the GENERAL lifecycle round-trips with E_OK; exit 1 on
// transport failure or a non-E_OK GENERAL result.
class TestabilityProbeCommand {
public:
    explicit TestabilityProbeCommand(CLI::App &app);

    bool parsed() const { return sub_->parsed(); }

    int run();

private:
    CLI::App *sub_ = nullptr;
    std::string dut_ip_;
    int port_ = 0;          // 0 -> testability::kDefaultPort, resolved in run()
    int service_id_ = -1;   // <0 -> testability::kDefaultServiceId
    int timeout_ms_ = 1000;
    bool use_tcp_ = false;   // SOME/IP over TCP instead of UDP
    bool skip_data_ = false; // GENERAL lifecycle only (no UDP data-plane loop)
    bool tcp_data_ = false;  // also exercise the TCP-group active-open SP loop
    bool icmp_echo_ = false; // also exercise the ICMP-group ECHO_REQUEST SP loop
    bool eth_ = false;       // also exercise the ETH INTERFACE_DOWN/UP SP loop
    bool ip_static_ = false; // also exercise the IP STATIC_ADDRESS/ROUTE SP loop

    // ETH loop parameters (required with --eth): the DUT-side interface to
    // toggle, and a SECOND DUT IP (on a different interface) whose reachability
    // is watched to observe the toggle's effect without severing the control
    // channel the commands ride on.
    std::string eth_iface_;
    std::string eth_observe_ip_;

    // IP STATIC loop parameters (with --ip-static): the DUT-side SECONDARY
    // interface to reconfigure, a fresh IPv4 to assign + observe reachable, and
    // its CIDR; plus an optional STATIC_ROUTE destination subnet + gateway (whose
    // table presence the check script observes). The control channel rides the
    // PRIMARY interface, untouched by the secondary's reconfiguration.
    std::string ip_static_iface_;
    std::string ip_static_addr_;
    int ip_static_cidr_ = 24;
    std::string ip_static_route_subnet_;
    std::string ip_static_route_gw_;
    int ip_static_route_cidr_ = 24;
};

}  // namespace tc8::cli
