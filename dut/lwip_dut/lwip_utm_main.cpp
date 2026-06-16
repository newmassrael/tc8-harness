// Standalone AUTOSAR Testability Upper Tester Module (UTM) on lwIP.
//
// The lwIP analog of dut/utm/utm_main.cpp: the same platform-agnostic
// tc8::testability::ProtocolServer (PRS_TPSP §6, AUTOSAR TC 1.2.0), here paired
// with the lwIP SocketBackend and run on the threaded lwIP unix-port stack —
// with NONE of the conformance fixture's harness-specific extras (no opcode
// Upper Tester, no demo apps). This is the OEM-/third-party-deployable form of
// the testability channel on an lwIP target: a real ECU swaps the tap netif for
// its own Ethernet driver and links this same server core unchanged.
//
// Usage: tc8-lwip-utm [PORT]
//   PORT  UDP port for the testability endpoint (default 30700).
//
// The stack address comes from the environment (TC8_LWIP_DUT_IP/MASK/GW) — the
// topology conf is the single place that owns the fixture subnet — exactly as
// the tc8-lwip-dut fixture takes it.

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "lwip/ip4_addr.h"

#include "lwip_stack_bringup.h"
#include "lwip_testability_server.h"
#include "tc8/testability_protocol.h"

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
            std::fprintf(stderr, "tc8-lwip-utm: invalid port '%s' (expected 1..65535)\n", argv[1]);
            return 2;
        }
        port = static_cast<std::uint16_t>(parsed);
    }

    const ip4_addr_t addr = tc8::lwip_dut::BringUpLwipStack();

    // Unlike tc8-lwip-dut — where the testability endpoint is additive to the
    // opcode UT and a bind failure is non-fatal — binding the port is this
    // binary's entire job, so a bind failure is a hard error.
    if (!tc8::lwip_dut::StartTestabilityServer(port)) {
        std::fprintf(stderr, "tc8-lwip-utm: failed to bind testability endpoint on UDP port %u\n",
                     static_cast<unsigned>(port));
        return 1;
    }

    char ip_text[IP4ADDR_STRLEN_MAX];
    ip4addr_ntoa_r(&addr, ip_text, sizeof(ip_text));
    std::fprintf(stderr, "tc8-lwip-utm: AUTOSAR testability UTM up at %s, UDP port %u\n",
                 ip_text, static_cast<unsigned>(port));

    tc8::lwip_dut::ParkUntilSigterm();

    // A userspace stack emits nothing when SIGKILLed; StopTestabilityServer
    // joins the server + async-event workers and closes the sockets (an
    // abort-close RSTs), the stand-in for the kernel closing sockets on Linux
    // process death.
    std::fprintf(stderr, "tc8-lwip-utm: SIGTERM — shutting down\n");
    tc8::lwip_dut::StopTestabilityServer();
    return 0;
}
