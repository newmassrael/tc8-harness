#include "lwip_testability_server.h"

#include <cstdio>
#include <memory>

#include "lwip_socket_backend.h"
#include "testability/protocol_server.h"

namespace tc8::lwip_dut {
namespace {

// Leaked deliberately like the UT server: the endpoint lives for the process
// lifetime and the fixture tears the process down via the topology conf. The
// pointer is kept so the SIGTERM path (StopTestabilityServer) can join + close.
tc8::testability::ProtocolServer *g_server = nullptr;

}  // namespace

void StartTestabilityServer(std::uint16_t port) {
    if (g_server != nullptr) {
        return;  // already started
    }
    auto *server =
        new tc8::testability::ProtocolServer(std::make_unique<LwipSocketBackend>());
    if (!server->start(port)) {
        std::fprintf(stderr,
                     "tc8-lwip-testability: endpoint start failed on UDP port %u (continuing — "
                     "additive to the opcode UT)\n",
                     port);
        delete server;
        return;
    }
    g_server = server;
    std::fprintf(stderr, "tc8-lwip-testability: AUTOSAR testability endpoint on UDP port %u\n",
                 port);
}

void StopTestabilityServer() {
    if (g_server != nullptr) {
        g_server->stop();
    }
}

}  // namespace tc8::lwip_dut
