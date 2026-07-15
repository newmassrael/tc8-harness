#pragma once

#include <string>

#include <CLI/CLI.hpp>

namespace tc8::cli {

// `tc8-harness testability-send` — one AUTOSAR Testability Protocol service
// primitive, addressed by GID/PID, with the decoded Response printed.
//
// The standard-protocol counterpart to `ut-ping`, which gives the in-house
// opcode Upper Tester (port 30600) a one-shot CLI. The standard endpoint (port
// 30700) had only `testability-probe`, whose flags toggle sections of a fixed
// scripted sweep — it has no --gid/--pid, so it can only reach the primitives
// its script names. A non-standard group (PRS_TPSP §6.6: OEM groups count down
// from 0x7F) is therefore unreachable from the CLI by construction, which is
// exactly the group an OEM attaches its own MiddlewareModule to.
//
// This command addresses any (GID, PID) and prints what comes back, so bringing
// up a DUT does not mean hand-assembling the 16-byte header in a throwaway
// script — the framing comes from the one codec SSOT
// (include/tc8/testability_protocol.h) via the same tester-side client the UTM
// SDK exports, so there is no second implementation to drift.
//
// Exit 0 when the DUT returned a well-formed Response with rid == E_OK; exit 1
// on transport failure, a malformed reply, or any non-E_OK Result ID (the RID is
// still printed — a DUT answering E_NTF is a real answer, and the caller decides
// whether that is the expected outcome).
class TestabilitySendCommand {
public:
    explicit TestabilitySendCommand(CLI::App &app);

    bool parsed() const { return sub_->parsed(); }

    int run();

private:
    CLI::App *sub_ = nullptr;
    std::string dut_ip_;
    std::string source_ip_;  // empty -> kernel-chosen source address
    std::string dat_hex_;    // request DAT as hex, empty -> no parameters
    int port_ = 0;           // 0 -> testability::kDefaultPort, resolved in run()
    int service_id_ = 0;     // 0 -> testability::kDefaultServiceId
    int gid_ = -1;           // required
    int pid_ = -1;           // required
    int timeout_ms_ = 1000;
    bool use_tcp_ = false;
};

}  // namespace tc8::cli
