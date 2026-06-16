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
// server thread. Additive, like the Linux tc8-dut: a bind failure is logged and
// the fixture keeps serving the opcode UT. No-op if already started.
void StartTestabilityServer(std::uint16_t port = tc8::testability::kDefaultPort);

// SIGTERM teardown: join the server + async-event worker threads and close
// every testability socket. Called from the main thread. No-op before
// StartTestabilityServer.
void StopTestabilityServer();

}  // namespace tc8::lwip_dut
