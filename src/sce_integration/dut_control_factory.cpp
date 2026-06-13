#include "sce_integration/dut_control_factory.h"

#include <cstdint>

#include "sce_integration/dut_control.h"
#include "sce_integration/dut_control_backend.h"
#include "sce_integration/test_config.h"
#include "stimulus/testability_client.h"
#include "tc8/testability_protocol.h"
#include "tc8/upper_tester_protocol.h"

namespace tc8::sce {

std::unique_ptr<IDutControl> makeDutControl(const ::tc8::TestConfig &cfg, int timeout_ms) {
    // Both backends reach the DUT at its capture-iface IPv4 — the same address
    // the opcode UT inject path targets (cfg.ipv4.dut_iface_ip). Source IP is
    // left kernel-chosen (0), matching `ut-ping` / `testability-probe`.
    const std::uint32_t dut_ip_be = cfg.ipv4.dut_iface_ip;

    switch (cfg.dut_control_backend) {
        case DutControlBackend::kTestability: {
            stimulus::TestabilityConfig tcfg;
            tcfg.dut_ip_be = dut_ip_be;
            tcfg.dut_port = testability::kDefaultPort;
            return std::make_unique<TestabilityControl>(tcfg, timeout_ms);
        }
        case DutControlBackend::kOpcode:
            break;
    }
    return std::make_unique<OpcodeUtControl>(dut_ip_be, ut::kPort, /*src_ip_be=*/0, timeout_ms);
}

}  // namespace tc8::sce
