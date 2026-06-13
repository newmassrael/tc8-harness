#pragma once

#include <memory>

// Backend factory for the Tier-2 DUT-control seam. Declared lightweight (only
// the `IDutControl` interface and `TestConfig` are referenced, both forward-
// declared) so the CLI — the single owner of the backend — is the only TU that
// pulls the concrete backends (dut_control.h, with its testability/upper-tester
// client includes); the 543 case headers and test_runner.h never see them.

namespace tc8 {
struct TestConfig;
}

namespace tc8::sce {

class IDutControl;

// Build the DUT-control backend selected by `cfg.dut_control_backend`, wired to
// the DUT endpoint carried in `cfg` (`cfg.ipv4.dut_iface_ip`):
//   kOpcode      -> OpcodeUtControl on the opcode UT port (30600).
//   kTestability -> TestabilityControl on the testability port (30700).
// `timeout_ms` bounds each control round trip. Never returns null.
std::unique_ptr<IDutControl> makeDutControl(const ::tc8::TestConfig &cfg, int timeout_ms = 1000);

}  // namespace tc8::sce
