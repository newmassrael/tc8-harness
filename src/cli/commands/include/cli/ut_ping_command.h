#pragma once

#include <string>

#include <CLI/CLI.hpp>

namespace tc8::cli {

// `tc8-harness ut-ping` — side-effect-free Upper Tester liveness +
// capability probe (UT OpPing, 0x15). Exit 0 when the DUT's UT server
// answered; exit 1 on timeout / malformed reply. smoke-test.sh's
// external / ssh-remote topology preflights call this so "the DUT
// lacks UT support" surfaces before any case runs instead of as a
// per-case timeout FAIL.
class UtPingCommand {
public:
    explicit UtPingCommand(CLI::App &app);

    bool parsed() const {
        return sub_->parsed();
    }

    int run();

private:
    CLI::App *sub_ = nullptr;
    std::string dut_ip_;
    std::string source_ip_;  // empty → kernel-chosen source address
    int port_ = 0;       // 0 → ut::kPort default, resolved in run()
    int timeout_ms_ = 1000;
};

}  // namespace tc8::cli
