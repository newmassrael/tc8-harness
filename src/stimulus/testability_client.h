#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "tc8/testability_protocol.h"

namespace tc8::stimulus {

// Tester-side AUTOSAR Testability Protocol client (PRS Testability TC 1.2.0,
// PRS_TPSP §6). The standard counterpart to the in-house opcode Upper Tester
// (upper_tester_client.h): it drives a DUT that implements the standard
// testability service over SOME/IP, so the harness is not limited to DUTs
// speaking our private opcodes. Wire framing + constants are the SSOT in
// include/tc8/testability_protocol.h; this layer adds the socket round trip
// and the GENERAL-group typed primitives.

// Configuration for one testability DUT endpoint.
struct TestabilityConfig {
    std::uint16_t service_id = testability::kDefaultServiceId;  // PRS_TPSP §6.1 SID
    std::uint32_t dut_ip_be = 0;                                // DUT IPv4 (network byte order)
    std::uint16_t dut_port = testability::kDefaultPort;         // PRS_TPSP §5.1 deployment port
    bool use_tcp = false;                                       // false = UDP (default), true = TCP
};

// Decoded testability response (PRS_TPSP §6.1 / PRS_TPSP §6.2). `ok` is false on socket error,
// timeout, a short/garbled reply, or a frame that is not a Response to this
// request. `tid` / `rid` are the raw testability bytes — note RID carries
// testability-specific values (0xFF E_NTF, 0xFC E_INV, ...) outside the
// SOME/IP standard return-code range, so they are kept as raw uint8.
struct TestabilityResponse {
    bool ok = false;
    std::uint8_t tid = 0;           // PRS_TPSP §6.2 message type id (0x80 on a well-formed response)
    std::uint8_t rid = 0;           // PRS_TPSP §6.8 result id
    std::vector<std::uint8_t> dat;  // PRS_TPSP §6.7 parameter data (payload after the 16-byte header)

    // A primitive that both reached the DUT and returned E_OK (PRS_TPSP §6.8).
    bool eok() const { return ok && rid == testability::kRidEOk; }
};

// Generic engine — the extension surface OEM-specific typed primitives build
// on. Frames one testability call (GID/PID + DAT) as a SOME/IP request, sends
// it over a kernel-routed socket (SOCK_DGRAM, or SOCK_STREAM when
// cfg.use_tcp), and blocks for the response. `src_ip_be` (0 = kernel-chosen)
// binds the source address — same contract as pingUpperTester's src bind.
// Returns ok=false on any transport or parse failure.
TestabilityResponse testabilityCall(const TestabilityConfig &cfg, std::uint8_t gid,
                                    std::uint8_t pid,
                                    const std::vector<std::uint8_t> &dat = {},
                                    int timeout_ms = 1000, std::uint32_t src_ip_be = 0);

// ── PRS_TPSP §6.10 GENERAL group typed wrappers (the standard, in-tree primitives) ──

struct TestabilityVersion {
    std::uint16_t major = 0;
    std::uint16_t minor = 0;
    std::uint16_t patch = 0;
};

// GET_VERSION (GENERAL / PID 0x01). Returns nullopt on transport failure or a
// malformed response; otherwise the DUT's reported testability protocol
// version (response DAT = major/minor/patch, uint16 x3, big-endian).
std::optional<TestabilityVersion> testabilityGetVersion(const TestabilityConfig &cfg,
                                                        int timeout_ms = 1000,
                                                        std::uint32_t src_ip_be = 0);

// START_TEST (GENERAL / PID 0x02) — no request parameters (PRS_TPSP §6.10 entry tag).
TestabilityResponse testabilityStartTest(const TestabilityConfig &cfg, int timeout_ms = 1000,
                                         std::uint32_t src_ip_be = 0);

// END_TEST (GENERAL / PID 0x03) — request DAT = tcId (uint16) + tsName (text,
// PRS_TPSP §6.7.5.2: UTF-8 with BOM and null termination wrapped in a vint8). Resets
// the Upper Tester (closes sockets, clears buffers, terminates active SPs).
TestabilityResponse testabilityEndTest(const TestabilityConfig &cfg, std::uint16_t tc_id,
                                       const std::string &ts_name, int timeout_ms = 1000,
                                       std::uint32_t src_ip_be = 0);

}  // namespace tc8::stimulus
