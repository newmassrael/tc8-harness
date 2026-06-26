/* lwIP configuration for the standalone AUTOSAR Testability UTM (tc8-lwip-utm),
 * and the reference config shipped in the utm-sdk-lwip component.
 *
 * SELF-CONTAINED (not layered on the conformance DUT's lwipopts.h): an OEM UTM
 * has nothing to do with the conformance fixture's per-case wire tuning, so this
 * carries only the generic unix-port infrastructure the testability core + lwIP
 * backend need, plus the IPv4 multicast a middleware module joins. The conformance
 * DUT keeps its OWN config (dut/lwip_dut/lwipopts.h); the two are independent
 * (different binaries, genuinely different requirements) and each is compiled, so
 * neither silently drifts. LWIP_PLATFORM_ASSERT is left at lwIP's default: the
 * loud+fatal custom sink is a conformance-verdict concern, not an SDK one, so the
 * UTM has no dependency on a fixture symbol and a replaced bring-up cannot break
 * the link.
 */
#ifndef TC8_LWIP_UTM_LWIPOPTS_H
#define TC8_LWIP_UTM_LWIPOPTS_H

/* ---------- platform / threading (unix port, threaded stack) ---------- */
#define NO_SYS                     0
#define LWIP_SOCKET                1
#define LWIP_NETCONN               1
#define LWIP_NETIF_API             1
#define LWIP_TCPIP_CORE_LOCKING    1
/* Arm the stack-wide core-lock assertion (unix port sys_check_core_locking),
 * validating the LOCK_TCPIP_CORE discipline the lwIP backend's raw-pcb / abort
 * bridges rely on. extern "C" so the C++ TUs match the C definition. */
#if !NO_SYS
#ifdef __cplusplus
extern "C" {
#endif
void sys_check_core_locking(void);
#ifdef __cplusplus
}
#endif
#define LWIP_ASSERT_CORE_LOCKED()  sys_check_core_locking()
#endif

/* ---------- protocol surface ---------- */
#define LWIP_IPV4                  1
#define LWIP_IPV6                  0
#define LWIP_ICMP                  1
#define LWIP_UDP                   1
#define LWIP_TCP                   1
#define LWIP_ARP                   1
/* The testability ICMP ECHO_REQUEST primitive emits through a raw pcb (lwIP has
 * no unprivileged ICMP datagram socket); see lwip_socket_backend.cpp. */
#define LWIP_RAW                   1

/* IPv4 multicast — the reason an OEM UTM links its own core: a middleware module
 * joins/leaves groups via the backend (joinMulticast / leaveMulticast,
 * lwip_socket_backend.cpp), which needs IGMP + the multicast TX socket options. */
#define LWIP_IGMP                  1
#define LWIP_MULTICAST_TX_OPTIONS  1

/* The middleware reactor's cross-thread waker is a 127.0.0.1 UDP socket pair
 * (lwip_socket_backend.cpp createWaker) — lwIP has no eventfd, and lwip_select
 * waits only on lwIP sockets, so the wake traverses the loopback path. */
#define LWIP_NETIF_LOOPBACK        1

/* A module's ARP cache-control primitive installs static entries
 * (etharp_add_static_entry, backend addStaticNeighbor). */
#define ETHARP_SUPPORT_STATIC_ENTRIES 1

/* ---------- socket options the backend uses ---------- */
#define SO_REUSE                   1   /* setReuseAddr */
#define LWIP_SO_RCVTIMEO           1   /* setRecvTimeoutMs */
#define LWIP_SO_SNDTIMEO           1   /* bounded sends */

/* ---------- TCP ---------- */
#define TCP_MSS                    1460
#define TCP_SND_BUF                (8 * TCP_MSS)
#define TCP_SND_QUEUELEN           (4 * TCP_SND_BUF / TCP_MSS)
#define TCP_WND                    (8 * TCP_MSS)
/* RFC 6528 ISN randomisation via the contrib tcp_isn addon, seeded in
 * BringUpLwipStack. Predictable ISNs are a security non-conformance; a UTM should
 * not ship them. The addon + tc8_lwip_hooks.h are transitive deps the OEM carries
 * on its lwIP/contrib include path (as it does for default_netif). */
#define LWIP_HOOK_TCP_ISN          lwip_hook_tcp_isn
#define LWIP_HOOK_FILENAME         "tc8_lwip_hooks.h"

/* ---------- memory sizing (generous for a middleware module + reactor) ---------- */
#define MEM_ALIGNMENT              4
#define MEM_SIZE                   (64 * 1024)
#define PBUF_POOL_SIZE             120
#define MEMP_NUM_TCP_PCB           8
#define MEMP_NUM_TCP_PCB_LISTEN    8
#define MEMP_NUM_TCP_SEG           64
#define MEMP_NUM_NETCONN           16
#define MEMP_NUM_UDP_PCB           16

#endif /* TC8_LWIP_UTM_LWIPOPTS_H */
