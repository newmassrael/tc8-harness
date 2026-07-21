// Standalone entry point for the tc8-utm SDK's testability-send tool.
//
// tc8-harness exposes this command as a `testability-send` subcommand, but that
// executable is gated behind TC8_BUILD_HARNESS and is absent from an SDK-only
// build (TC8_BUILD_HARNESS=OFF, built without vsomeip/libpcap/libtins). The
// addressed primitive caller has no dependency on the harness wire runner — only
// the SDK-exported tc8_testability_client and the codec SSOT — so it ships as its
// own small executable that a find_package(tc8-utm) consumer gets in bin/,
// beside the client library it already links. The command implementation is the
// same TestabilitySendCommand the harness hosts, so the two footprints cannot
// drift from the single codec/client path.
#include <CLI/CLI.hpp>

#include "cli/testability_send_command.h"

int main(int argc, char **argv) {
    CLI::App app{
        "tc8-testability-send — send one AUTOSAR Testability service primitive "
        "(--gid/--pid/--dat) to a DUT and print the decoded Response"};

    tc8::cli::TestabilitySendCommand command(
        app, tc8::cli::TestabilitySendCommand::AsRootCommand{});

    CLI11_PARSE(app, argc, argv);
    return command.run();
}
