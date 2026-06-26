#include "lwip_stack_bringup.h"

#include <sys/random.h>
#include <unistd.h>

#include <csignal>
#include <cstdint>
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

// lwipopts.h routes LWIP_PLATFORM_ASSERT here: loud + fatal, because a tripped
// stack invariant means every verdict after it is untrustworthy. Defined once
// here so every binary that links this bring-up TU gets the sink (the core
// lwIP TUs reference it via the LWIP_PLATFORM_ASSERT macro).
extern "C" void tc8_lwip_platform_assert(const char *msg, int line,
                                         const char *file) {
    std::fprintf(stderr, "tc8-lwip: assert \"%s\" at %s:%d\n", msg, file, line);
    std::abort();
}

namespace tc8::lwip_dut {
namespace {

// SIGTERM lands here only to wake the main thread out of pause(); the actual
// teardown runs on the main thread after ParkUntilSigterm returns, never in
// signal context.
volatile sig_atomic_t g_terminate = 0;

extern "C" void handle_term(int) { g_terminate = 1; }

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
        std::fprintf(stderr, "tc8-lwip: %s='%s' is not a valid IPv4 address\n", var, text);
        std::exit(1);
    }
    return out;
}

}  // namespace

ip4_addr_t BringUpLwipStack() {
    const ip4_addr_t addr = addrFromEnv("TC8_LWIP_DUT_IP",   "172.16.0.2");
    const ip4_addr_t mask = addrFromEnv("TC8_LWIP_DUT_MASK", "255.255.255.0");
    const ip4_addr_t gw   = addrFromEnv("TC8_LWIP_DUT_GW",   "172.16.0.1");

    // RFC 6528 ISN secret — must be seeded before the first TCP pcb is created
    // (LWIP_HOOK_TCP_ISN fires on every connect/listen ISS pick).
    std::uint8_t isn_secret[16];
    if (getrandom(isn_secret, sizeof(isn_secret), 0) !=
        static_cast<ssize_t>(sizeof(isn_secret))) {
        std::fprintf(stderr,
                     "tc8-lwip: getrandom for the RFC 6528 ISN secret failed; "
                     "refusing to run with a predictable ISN\n");
        std::exit(1);
    }
    lwip_init_tcp_isn(0, isn_secret);

    sys_sem_t init_sem;
    if (sys_sem_new(&init_sem, 0) != ERR_OK) {
        std::fprintf(stderr, "tc8-lwip: sys_sem_new failed\n");
        std::exit(1);
    }
    tcpip_init(tcpip_init_done, &init_sem);
    sys_sem_wait(&init_sem);
    sys_sem_free(&init_sem);

    LOCK_TCPIP_CORE();
    init_default_netif(&addr, &mask, &gw);
    netif_set_up(netif_default);
    netif_set_link_up(netif_default);
    UNLOCK_TCPIP_CORE();

    // Fault-injection hooks are NOT installed here: a UTM is not a fault fixture,
    // and this bring-up is exported (utm-sdk-lwip) for out-of-tree UTMs. The
    // conformance DUT calls installFaultHooks() (lwip_fault_hooks.h) right after
    // this returns; see that header for why the gap between the two is benign.
    return addr;
}

void ParkUntilSigterm() {
    struct sigaction sa = {};
    sa.sa_handler = handle_term;
    sigaction(SIGTERM, &sa, nullptr);

    while (g_terminate == 0) {
        pause();
    }
}

}  // namespace tc8::lwip_dut
