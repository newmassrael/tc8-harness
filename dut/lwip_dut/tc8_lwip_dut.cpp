// Minimal lwIP DUT for tc8-harness external-topology runs.
//
// Brings up the threaded lwIP stack on a preconfigured tap netif
// (PRECONFIGURED_TAPIF env, consumed by the unix-port tapif driver),
// assigns a static address, starts the Upper Tester server and parks
// the main thread forever. The stack itself (ARP/ICMP/IP/UDP/TCP input
// paths) is the device under test — no demo apps, no console, no
// self-exit.
//
// Address configuration comes from the environment so the topology
// conf is the single place that knows the fixture subnet:
//   TC8_LWIP_DUT_IP    (default 172.16.0.2)
//   TC8_LWIP_DUT_MASK  (default 255.255.255.0)
//   TC8_LWIP_DUT_GW    (default 172.16.0.1)

#include <sys/random.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>

#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/sys.h"
#include "lwip/tcpip.h"

// Upstream header ships without C++ linkage guards.
extern "C" {
#include "examples/example_app/default_netif.h"
}
#include "tcp_isn.h"

#include "lwip_ut_server.h"

// lwipopts.h routes LWIP_PLATFORM_ASSERT here: loud + fatal, because a
// tripped stack invariant means every verdict after it is untrustworthy.
extern "C" void tc8_lwip_platform_assert(const char *msg, int line,
                                         const char *file) {
    std::fprintf(stderr, "tc8-lwip-dut: assert \"%s\" at %s:%d\n",
                 msg, file, line);
    std::abort();
}

namespace {

void tcpip_init_done(void *sem) {
    sys_sem_signal(static_cast<sys_sem_t *>(sem));
}

ip4_addr_t addrFromEnv(const char *var, const char *fallback) {
    const char *text = std::getenv(var);
    if (text == nullptr || text[0] == '\0') {
        text = fallback;
    }
    ip4_addr_t out;
    if (!ip4addr_aton(text, &out)) {
        std::fprintf(stderr,
                     "tc8-lwip-dut: %s='%s' is not a valid IPv4 address\n",
                     var, text);
        std::exit(1);
    }
    return out;
}

}  // namespace

int main() {
    const ip4_addr_t addr = addrFromEnv("TC8_LWIP_DUT_IP",   "172.16.0.2");
    const ip4_addr_t mask = addrFromEnv("TC8_LWIP_DUT_MASK", "255.255.255.0");
    const ip4_addr_t gw   = addrFromEnv("TC8_LWIP_DUT_GW",   "172.16.0.1");

    // RFC 6528 ISN secret — must be seeded before the first TCP pcb is
    // created (LWIP_HOOK_TCP_ISN fires on every connect/listen ISS pick).
    std::uint8_t isn_secret[16];
    if (getrandom(isn_secret, sizeof(isn_secret), 0)
        != static_cast<ssize_t>(sizeof(isn_secret))) {
        std::fprintf(stderr,
                     "tc8-lwip-dut: getrandom for the RFC 6528 ISN secret "
                     "failed; refusing to run with a predictable ISN\n");
        return 1;
    }
    lwip_init_tcp_isn(0, isn_secret);

    sys_sem_t init_sem;
    if (sys_sem_new(&init_sem, 0) != ERR_OK) {
        std::fprintf(stderr, "tc8-lwip-dut: sys_sem_new failed\n");
        return 1;
    }
    tcpip_init(tcpip_init_done, &init_sem);
    sys_sem_wait(&init_sem);
    sys_sem_free(&init_sem);

    LOCK_TCPIP_CORE();
    init_default_netif(&addr, &mask, &gw);
    netif_set_up(netif_default);
    netif_set_link_up(netif_default);
    UNLOCK_TCPIP_CORE();

    tc8::lwip_dut::StartUpperTesterServer(addr.addr);

    char ip_text[IP4ADDR_STRLEN_MAX];
    ip4addr_ntoa_r(&addr, ip_text, sizeof(ip_text));
    std::fprintf(stderr, "tc8-lwip-dut: stack up at %s\n", ip_text);

    for (;;) {
        pause();
    }
    return 0;
}
