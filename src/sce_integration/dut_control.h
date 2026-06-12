#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "stimulus/testability_client.h"
#include "stimulus/upper_tester_client.h"
#include "tc8/testability_protocol.h"
#include "tc8/upper_tester_protocol.h"

namespace tc8::sce {

// Upper-Tester-channel abstraction so the harness can drive either an in-house
// opcode DUT (the reference tc8-dut / lwIP DUT) or a standard AUTOSAR
// Testability Protocol DUT behind one handle.
//
// The interface captures the genuinely cross-cutting contract — UT-channel
// liveness plus the test-session lifecycle. The session lifecycle is exactly
// what the standard protocol ADDS over the opcode protocol: testability frames
// START_TEST / END_TEST (PRS_TPSP §6.10), whereas the opcode protocol has no
// session framing and relies on per-case DUT respawn. A backend-agnostic
// driver can therefore bracket a case with startTest()/endTest() and get the
// right behaviour on either DUT. Protocol-specific stimulus (opcode requests
// vs typed service primitives) stays on the concrete backend — see
// TestabilityControl::call() for the standard generic engine.
//
// Existing cases do not use this seam; they call the opcode builders directly
// and are unaffected. It is the entry point for out-of-tree OEM cases and for
// `tc8-harness testability-probe`.
class IDutControl {
public:
    virtual ~IDutControl() = default;

    // Is the UT channel reachable? (opcode: OpPing; testability: GET_VERSION.)
    virtual bool probe() = 0;

    // Begin a test session. Opcode backend: no-op (returns true) — the
    // in-house protocol has no session frame and isolates via respawn.
    // Testability backend: START_TEST (GENERAL/0x02).
    virtual bool startTest() = 0;

    // End / reset a test session. Opcode backend: no-op. Testability backend:
    // END_TEST (GENERAL/0x03) — closes sockets, clears buffers.
    virtual bool endTest() = 0;

    // Human-readable backend tag for diagnostics / probe output.
    virtual const char *backendName() const = 0;
};

// Adapter over the in-house opcode Upper Tester (upper_tester_client.h). Wraps
// the existing builders/transport with no behaviour change. Kernel-routed
// SOCK_DGRAM probe (matching `ut-ping`); a future revision can route data-plane
// triggers through OpTriggerSendUdp if a unified driver needs them.
class OpcodeUtControl final : public IDutControl {
public:
    explicit OpcodeUtControl(std::uint32_t dut_ip_be, std::uint16_t port = ut::kPort,
                             std::uint32_t src_ip_be = 0, int timeout_ms = 1000)
        : dut_ip_be_(dut_ip_be), port_(port), src_ip_be_(src_ip_be), timeout_ms_(timeout_ms) {}

    bool probe() override {
        return stimulus::pingUpperTester(dut_ip_be_, port_, timeout_ms_, src_ip_be_)
            .has_value();
    }
    // The opcode protocol has no session framing — per-case respawn provides
    // isolation, so the lifecycle calls are well-defined no-ops.
    bool startTest() override { return true; }
    bool endTest() override { return true; }
    const char *backendName() const override { return "opcode-ut"; }

private:
    std::uint32_t dut_ip_be_;
    std::uint16_t port_;
    std::uint32_t src_ip_be_;
    int timeout_ms_;
};

// Adapter over the AUTOSAR Testability Protocol client (testability_client.h).
// Besides the IDutControl lifecycle it exposes the protocol's generic
// `call(gid, pid, dat)` engine, which OEM-specific typed service-primitive
// wrappers (written out of tree) build on.
class TestabilityControl final : public IDutControl {
public:
    explicit TestabilityControl(const stimulus::TestabilityConfig &cfg, int timeout_ms = 1000,
                                std::uint32_t src_ip_be = 0)
        : cfg_(cfg), timeout_ms_(timeout_ms), src_ip_be_(src_ip_be) {}

    bool probe() override { return getVersion().has_value(); }
    bool startTest() override {
        return stimulus::testabilityStartTest(cfg_, timeout_ms_, src_ip_be_).eok();
    }
    bool endTest() override {
        return stimulus::testabilityEndTest(cfg_, /*tc_id=*/0, "tc8-harness", timeout_ms_,
                                            src_ip_be_)
            .eok();
    }
    const char *backendName() const override { return "autosar-testability"; }

    // GET_VERSION (GENERAL/0x01).
    std::optional<stimulus::TestabilityVersion> getVersion() {
        return stimulus::testabilityGetVersion(cfg_, timeout_ms_, src_ip_be_);
    }

    // Generic service-primitive call — the standard extension surface.
    stimulus::TestabilityResponse call(std::uint8_t gid, std::uint8_t pid,
                                       const std::vector<std::uint8_t> &dat = {}) {
        return stimulus::testabilityCall(cfg_, gid, pid, dat, timeout_ms_, src_ip_be_);
    }

    const stimulus::TestabilityConfig &config() const { return cfg_; }

private:
    stimulus::TestabilityConfig cfg_;
    int timeout_ms_;
    std::uint32_t src_ip_be_;
};

}  // namespace tc8::sce
