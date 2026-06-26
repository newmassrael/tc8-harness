// Minimal lwIP DUT for tc8-harness external-topology runs.
//
// Brings up the threaded lwIP stack on a preconfigured tap netif (see
// lwip_stack_bringup.h), starts the Upper Tester servers and parks the main
// thread until SIGTERM. The stack itself (ARP/ICMP/IP/UDP/TCP input paths) is
// the device under test — no demo apps, no console, no self-exit. Address
// configuration comes from the environment (TC8_LWIP_DUT_IP/MASK/GW) so the
// topology conf is the single place that knows the fixture subnet.

#include <cstdio>
#include <memory>

#include "lwip/ip4_addr.h"
#include "lwip/netif.h"

#include "lwip_fault_hooks.h"
#include "lwip_socket_backend.h"
#include "lwip_stack_bringup.h"
#include "lwip_stack_probe.h"
#include "lwip_ut_extensions.h"
#include "tc8/testability_protocol.h"
#include "testability/protocol_server.h"
#include "upper_tester/ut_server.h"

int main() {
    const ip4_addr_t addr = tc8::lwip_dut::BringUpLwipStack();
    // Arm the conformance fault seams (egress field / ingress reaction), kept out
    // of the exported bring-up so the UTM carries no fixture fault code. Before
    // any server starts, so no flavor can be armed in the meantime.
    tc8::lwip_dut::installFaultHooks();

    // TC8 §4.8.5 Upper Tester channel, running on the platform-agnostic
    // UpperTesterServer core (shared verbatim with the Linux tc8-dut) paired with
    // this fixture's lwIP adapters — the lwIP SocketBackend (socket primitives)
    // and StackProbe (TCP-info / original-destination introspection). The §4.2.4.2
    // ARP cache conditioning opcode (0x17) is lwIP-specific, so it registers onto
    // the core rather than being baked in (the Linux DUT conditions ARP via netns
    // sysctls instead). The directed broadcast the §4.4.4.5 ADDRESSING_02 data
    // listener silently discards is derived from the netif's address + mask.
    const struct netif *nif = netif_default;
    const std::uint32_t if_ip_be = ip4_addr_get_u32(netif_ip4_addr(nif));
    const std::uint32_t if_mask_be = ip4_addr_get_u32(netif_ip4_netmask(nif));
    const std::uint32_t iface_bcast_be = (if_ip_be & if_mask_be) | ~if_mask_be;

    tc8::ut::UpperTesterServer upper_tester{std::make_unique<tc8::lwip_dut::LwipSocketBackend>(),
                                            std::make_unique<tc8::lwip_dut::LwipStackProbe>()};
    tc8::lwip_dut::registerLwipUtExtensions(upper_tester);
    if (!upper_tester.start(addr.addr, iface_bcast_be)) {
        // Abort, do not limp on: a half-up DUT (stack answering, UT dead) is
        // exactly the state the topology preflight cannot distinguish from "UT
        // not implemented".
        std::fprintf(stderr, "tc8-lwip-dut: upper-tester start failed\n");
        return 1;
    }

    // AUTOSAR Testability Protocol endpoint (PRS_TPSP §6, TC 1.2.0) — the same
    // platform-agnostic ProtocolServer the Linux tc8-dut owns in dut_main.cpp,
    // here paired with the lwIP SocketBackend and started as an additive listener
    // alongside the opcode UT above: a bind failure is non-fatal, so the fixture
    // keeps serving the opcode UT cases. tc8-lwip-utm hoists this same endpoint
    // into a standalone binary.
    tc8::testability::ProtocolServer testability{
        std::make_unique<tc8::lwip_dut::LwipSocketBackend>()};
    if (!testability.start()) {
        std::fprintf(stderr,
                     "tc8-lwip-dut: testability endpoint start failed (continuing — additive to "
                     "the opcode UT)\n");
    }

    char ip_text[IP4ADDR_STRLEN_MAX];
    ip4addr_ntoa_r(&addr, ip_text, sizeof(ip_text));
    std::fprintf(stderr, "tc8-lwip-dut: stack up at %s\n", ip_text);

    // SIGTERM = orderly teardown. A userspace stack emits nothing when SIGKILLed,
    // so case-leaked UT connections would orphan their tester-side halves in
    // FIN-WAIT-2 and swallow the next case's SYN on the same deterministic port
    // quad; stop(abort=true) RSTs every live slot first — the fixture's
    // equivalent of the Linux DUT's kernel closing sockets on process death.
    tc8::lwip_dut::ParkUntilSigterm();

    upper_tester.stop(/*abort=*/true);
    // Join the testability server + its async workers and close its sockets.
    testability.stop();
    std::fprintf(stderr, "tc8-lwip-dut: SIGTERM — UT slots aborted, exiting\n");
    return 0;
}
