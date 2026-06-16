#pragma once

#include <string>

#include <CLI/CLI.hpp>

namespace tc8::cli {

// `tc8-harness testability-probe` — exercises a DUT's AUTOSAR Testability
// Protocol endpoint (PRS Testability TC 1.2.0) end to end: GET_VERSION +
// START_TEST + a UDP CREATE_AND_BIND / SEND_DATA / CLOSE_SOCKET data-plane
// loop + (with --tcp-data) a TCP CREATE_AND_BIND / CONNECT / SEND_DATA /
// CLOSE_SOCKET active-open loop + (with --icmp) an ICMP ECHO_REQUEST loop +
// END_TEST, reporting each Result ID. The
// standard-protocol counterpart to `ut-ping` (which speaks the in-house opcode
// UT). Exit 0 when the GENERAL lifecycle round-trips with E_OK; exit 1 on
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
};

}  // namespace tc8::cli
