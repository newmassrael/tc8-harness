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
//
// One implementation, two build footprints. Bound onto a subcommand it is the
// tc8-harness `testability-send` verb; bound onto the root CLI::App it is the
// standalone tc8-testability-send tool the tc8-utm SDK installs. An SDK-only
// build (TC8_BUILD_HARNESS=OFF) has no wire runner and so no subcommand host,
// but the addressed primitive caller depends only on the SDK-exported client —
// not on vsomeip/libpcap/libtins — so it ships as its own executable beside the
// client library. The option set and run() are identical either way, so the two
// footprints cannot drift from the single codec/client path.
class TestabilitySendCommand {
public:
    // Register a `testability-send` subcommand on `app` (the tc8-harness verb).
    explicit TestabilitySendCommand(CLI::App &app);

    // Bind the same options directly onto `app` as the root command, with no
    // subcommand layer (the standalone tc8-testability-send tool). The tag makes
    // the overload selection explicit at the call site.
    struct AsRootCommand {};
    TestabilitySendCommand(CLI::App &app, AsRootCommand);

    // Whether this command was selected. A root binding is always the selected
    // command; a subcommand binding defers to whether CLI matched it.
    bool parsed() const { return sub_ == nullptr || sub_->parsed(); }

    int run();

private:
    // Add the shared option/flag set to `target` (a subcommand or the root app).
    void addOptions(CLI::App &target);

    CLI::App *sub_ = nullptr;  // null when bound as the root command
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
