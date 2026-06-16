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

#include "lwip_socket_backend.h"
#include "lwip_stack_bringup.h"
#include "lwip_ut_server.h"
#include "tc8/testability_protocol.h"
#include "testability/protocol_server.h"

int main() {
    const ip4_addr_t addr = tc8::lwip_dut::BringUpLwipStack();

    tc8::lwip_dut::StartUpperTesterServer(addr.addr);

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

    // SIGTERM = orderly teardown. A userspace stack emits nothing when
    // SIGKILLed, so case-leaked UT connections would orphan their tester-side
    // halves in FIN-WAIT-2 and swallow the next case's SYN on the same
    // deterministic port quad; the aborts below RST every open slot first — the
    // fixture's equivalent of the Linux DUT's kernel closing sockets on process
    // death.
    tc8::lwip_dut::ParkUntilSigterm();

    tc8::lwip_dut::AbortUpperTesterSlots();
    // Join the testability server + its async workers and close its sockets (an
    // abort-close RSTs, the fixture's stand-in for the kernel closing sockets on
    // Linux process death).
    testability.stop();
    std::fprintf(stderr, "tc8-lwip-dut: SIGTERM — UT slots aborted, exiting\n");
    return 0;
}
