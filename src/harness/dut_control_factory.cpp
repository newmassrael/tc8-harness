#include "sce_integration/dut_control_factory.h"

#include <cstdint>

#include "sce_integration/dut_control.h"
#include "sce_integration/dut_control_backend.h"
#include "sce_integration/test_config.h"
#include "tc8/testability_client.h"
#include "tc8/testability_protocol.h"
#include "tc8/upper_tester_protocol.h"

namespace tc8::sce {

std::unique_ptr<IDutControl> makeDutControl(const ::tc8::TestConfig &cfg, std::string_view iface,
                                            int timeout_ms) {
    // Both backends reach the DUT at its capture-iface IPv4 — the same address
    // the opcode UT inject path targets (cfg.ipv4.dut_iface_ip). Source IP is
    // left kernel-chosen (0), matching `ut-ping` / `testability-probe`.
    const std::uint32_t dut_ip_be = cfg.ipv4.dut_iface_ip;

    switch (cfg.dut_control_backend) {
        case DutControlBackend::kTestability: {
            testability::TestabilityConfig tcfg;
            tcfg.dut_ip_be = dut_ip_be;
            tcfg.dut_port = testability::kDefaultPort;
            return std::make_unique<TestabilityControl>(tcfg, timeout_ms);
        }
        case DutControlBackend::kOpcode:
            break;
    }
    // The OpQueryCapabilities (0x16) probe that resolves DUT-derived fault caps
    // is sourced from the tester ALIAS, not the (kernel-chosen) primary tester
    // IP: §4.2 cold-cache cases require the DUT's primary-IP ARP entry to be
    // ABSENT when the case starts, but the cap probe's UT response would make the
    // DUT ARP-resolve its source. The fixture readiness probe already warms the
    // alias (and no §4.2 assertion references it — see lwip-tap.conf), so probing
    // from the alias lets the DUT answer from a cached entry, emitting no ARP and
    // leaving the cold-cache premise intact. 0 (no alias configured) falls back to
    // kernel-chosen, harmless on backends/DUTs where no `_NEG` runs.
    // Raw-injection transport for the sub-interfaces that must not provoke a
    // tester-side ARP (see OpcodeRawTransport). The DUT MAC and tester IP are the
    // same identities the direct opcode-builder stimulus paths already inject
    // with, so a case routed over the seam puts the SAME frame on the wire as the
    // legacy path it replaces.
    OpcodeRawTransport raw;
    raw.iface = std::string(iface);
    raw.tester_ip_be = cfg.ipv4.tester_ip;
    raw.dut_mac = cfg.dut.mac;
    return std::make_unique<OpcodeUtControl>(dut_ip_be, ut::kPort, /*src_ip_be=*/0, timeout_ms,
                                             /*cap_probe_src_ip_be=*/cfg.ipv4.tester_alias_ip,
                                             std::move(raw));
}

}  // namespace tc8::sce
