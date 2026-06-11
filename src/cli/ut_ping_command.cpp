#include "cli/ut_ping_command.h"

#include <cstdio>

#include <arpa/inet.h>

#include "stimulus/upper_tester_client.h"
#include "tc8/upper_tester_protocol.h"

namespace tc8::cli {

UtPingCommand::UtPingCommand(CLI::App &app) {
    sub_ = app.add_subcommand(
        "ut-ping",
        "Probe the DUT's Upper Tester (side-effect-free OpPing round trip)");
    sub_->add_option("--dut-ip", dut_ip_, "DUT IPv4 address")->required();
    sub_->add_option("--port", port_,
                     "UT UDP port (default: protocol constant 30600)");
    sub_->add_option("-t,--timeout", timeout_ms_,
                     "Reply timeout in milliseconds")
        ->capture_default_str();
    sub_->add_option(
        "--source-ip", source_ip_,
        "Bind the probe's source to this local IPv4 address (default: "
        "kernel-chosen). Topology fixtures whose DUT cannot be "
        "ARP-flushed per case pass a tester alias here so the probe's "
        "reply path does not warm the DUT's ARP entry for the primary "
        "tester IP — §4.2 cold-cache cases assert on that entry's "
        "absence.");
}

int UtPingCommand::run() {
    in_addr addr{};
    if (::inet_pton(AF_INET, dut_ip_.c_str(), &addr) != 1) {
        std::fprintf(stderr, "ut-ping: invalid DUT IPv4 address '%s'\n",
                     dut_ip_.c_str());
        return 1;
    }
    in_addr src_addr{};
    if (!source_ip_.empty() &&
        ::inet_pton(AF_INET, source_ip_.c_str(), &src_addr) != 1) {
        std::fprintf(stderr, "ut-ping: invalid source IPv4 address '%s'\n",
                     source_ip_.c_str());
        return 1;
    }
    const auto port = port_ > 0 ? static_cast<std::uint16_t>(port_)
                                : ut::kPort;

    const auto result = stimulus::pingUpperTester(addr.s_addr, port,
                                                  timeout_ms_,
                                                  src_addr.s_addr);
    if (!result.has_value()) {
        std::fprintf(stderr,
                     "ut-ping: no Upper Tester reply from %s:%u within %d ms "
                     "(DUT down, UT not implemented, or port mismatch)\n",
                     dut_ip_.c_str(), port, timeout_ms_);
        return 1;
    }

    std::printf("ut-ping: %s:%u answered — UT implemented up to opcode "
                "0x%02X (reference tc8-dut: 0x%02X)\n",
                dut_ip_.c_str(), port, result->max_opcode,
                ut::kMaxImplementedOpcode);
    return 0;
}

}  // namespace tc8::cli
