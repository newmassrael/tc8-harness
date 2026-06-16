#pragma once

#include <cstdint>

#include "tc8/testability_protocol.h"

namespace tc8::lwip_dut {

// AUTOSAR Testability Protocol endpoint (PRS_TPSP §6, AUTOSAR TC 1.2.0) for the
// lwIP DUT fixture. A thin entry point over the shared, platform-agnostic
// tc8::testability::ProtocolServer paired with the lwIP SocketBackend (see
// lwip_socket_backend.h) — the protocol logic, including the OEM seam, is the
// same translation unit the Linux tc8-dut runs; only the socket adapter differs.

// Bind the testability UDP listener (default PRS_TPSP port 30700) and start the
// server thread. Returns true once bound; on a bind failure it logs and returns
// false. The tc8-lwip-dut fixture ignores the result (additive — it keeps
// serving the opcode UT), while the standalone tc8-lwip-utm treats it as fatal.
// No-op returning true if already started.
bool StartTestabilityServer(std::uint16_t port = tc8::testability::kDefaultPort);

// SIGTERM teardown: join the server + async-event worker threads and close
// every testability socket. Called from the main thread. No-op before
// StartTestabilityServer.
void StopTestabilityServer();

}  // namespace tc8::lwip_dut
