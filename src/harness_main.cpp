#include <cstdio>
#include <exception>
#include <optional>
#include <string>

#include <CLI/CLI.hpp>

#include "cli/live_command.h"
#include "cli/replay_command.h"
#include "cli/test_command.h"

int main(int argc, char** argv) {
    std::setvbuf(stdout, nullptr, _IOLBF, 0);

    CLI::App app{"tc8-harness — OPEN Alliance TC8 v3.0 conformance harness"};
    app.require_subcommand(1);

    // Top-level override. When unset each subcommand picks its own default
    // (live/replay → bpf::someip(); test → per-case BpfGroup).
    std::string bpf;
    auto* bpf_opt = app.add_option(
        "-f,--bpf", bpf,
        "BPF filter override (default: command-specific)");

    tc8::cli::LiveCommand   live(app);
    tc8::cli::ReplayCommand replay(app);
    tc8::cli::TestCommand   test(app);

    CLI11_PARSE(app, argc, argv);

    const std::optional<std::string> bpf_override =
        bpf_opt->count() > 0 ? std::optional<std::string>{bpf} : std::nullopt;

    try {
        if (live.parsed())   return live.run(bpf_override);
        if (replay.parsed()) return replay.run(bpf_override);
        if (test.parsed())   return test.run(bpf_override);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "error: %s\n", e.what());
        return 1;
    }
    return 0;
}
