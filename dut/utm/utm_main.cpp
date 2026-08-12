// Standalone AUTOSAR Testability Upper Tester Module (UTM).
//
// Runs the testability endpoint (PRS_TPSP §6, AUTOSAR TC 1.2.0) as a
// self-contained process, independent of the vsomeip / CommonAPI stack that
// tc8-dut carries. This is the OEM-/third-party-deployable form of the
// testability channel: the same TestabilityServer that tc8-dut hosts as one
// additive listener, hoisted into its own binary so it can run on a real ECU
// as the standard Upper Tester Module that TC8 conformance cases reference as
// their Upper Tester channel ("as an example", per the TC8 spec).
//
// The wire framing + codec are the SSOT in include/tc8/testability_protocol.h,
// shared verbatim with the harness-side client; the server logic is reused
// unchanged from dut/dut_service/testability_server.{h,cpp}. Only this thin
// signal-driven entry point is new.
//
// Usage: tc8-utm [PORT]
//   PORT  UDP port for the testability endpoint (default 30700).

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <thread>

#include "tc8/linux_socket_backend.h"
#include "tc8/testability_protocol.h"
#include "tc8/testability/protocol_server.h"

namespace {

std::atomic<bool> g_stop{false};

void onSignal(int /*signum*/) { g_stop.store(true); }

}  // namespace

int main(int argc, char **argv) {
    std::setvbuf(stdout, nullptr, _IOLBF, 0);

    std::uint16_t port = tc8::testability::kDefaultPort;
    if (argc > 1) {
        if (std::strcmp(argv[1], "-h") == 0 || std::strcmp(argv[1], "--help") == 0) {
            std::printf("usage: %s [PORT]\n", argv[0]);
            std::printf("  PORT  UDP port for the testability endpoint (default %u)\n",
                        static_cast<unsigned>(tc8::testability::kDefaultPort));
            return 0;
        }
        char *end = nullptr;
        const long parsed = std::strtol(argv[1], &end, 10);
        if (end == argv[1] || *end != '\0' || parsed < 1 || parsed > 65535) {
            std::fprintf(stderr, "tc8-utm: invalid port '%s' (expected 1..65535)\n", argv[1]);
            return 2;
        }
        port = static_cast<std::uint16_t>(parsed);
    }

    std::signal(SIGINT, onSignal);
    std::signal(SIGTERM, onSignal);

    // Unlike tc8-dut — where the testability endpoint is additive and a bind
    // failure is non-fatal — binding the port is this binary's entire job, so a
    // bind failure is a hard error.
    tc8::testability::ProtocolServer server{std::make_unique<tc8::dut::LinuxSocketBackend>()};
    if (!server.start(port)) {
        std::fprintf(stderr, "tc8-utm: failed to bind testability endpoint on UDP port %u\n",
                     static_cast<unsigned>(port));
        return 1;
    }
    std::printf("tc8-utm: AUTOSAR testability UTM listening on UDP port %u\n",
                static_cast<unsigned>(port));

    while (!g_stop.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    std::printf("tc8-utm: shutting down\n");
    server.stop();
    return 0;
}
