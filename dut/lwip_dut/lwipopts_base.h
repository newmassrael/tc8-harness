/* Product-neutral lwIP unix-port infrastructure shared by the tc8-harness lwIP
 * binaries. The conformance DUT (dut/lwip_dut/lwipopts.h) and the standalone UTM
 * (dut/lwip_dut/utm/lwipopts.h, also the utm-sdk-lwip reference) each #include this
 * and add only their own delta — so the options the two genuinely agree on have a
 * SINGLE source of truth here, and neither inherits the other's concerns. This
 * file carries NO conformance-case tuning and NO assert sink (the DUT's), and NO
 * multicast (the UTM's).
 */
#ifndef TC8_LWIP_LWIPOPTS_BASE_H
#define TC8_LWIP_LWIPOPTS_BASE_H

/* ---------- platform / threading (unix port, threaded stack) ---------- */
#define NO_SYS                     0
#define LWIP_SOCKET                1
#define LWIP_NETCONN               1
#define LWIP_NETIF_API             1
#define LWIP_TCPIP_CORE_LOCKING    1
/* Arm the stack-wide core-lock assertion (unix port sys_check_core_locking),
 * validating the LOCK_TCPIP_CORE discipline the raw-pcb / abort bridges rely on.
 * extern "C" because lwipopts.h is included by the C++ TUs, whose default linkage
 * would otherwise not match the C definition. */
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

/* ---------- IPv4 protocol surface ---------- */
#define LWIP_IPV4                  1
/* TC8 v3.0 is IPv4-only; both binaries keep IPv6 off to stay silent on the wire. */
#define LWIP_IPV6                  0
#define LWIP_ICMP                  1
#define LWIP_UDP                   1
#define LWIP_TCP                   1
#define LWIP_ARP                   1
/* The testability ICMP ECHO_REQUEST primitive emits through a raw pcb — lwIP has
 * no unprivileged ICMP datagram socket. Egress only; no raw receive callback. */
#define LWIP_RAW                   1
/* Generic IPv4 fragmentation / reassembly. The bucket-lifetime tuning is each
 * binary's own (the DUT pins it to a conformance window). */
#define IP_REASSEMBLY              1
#define IP_FRAG                    1
/* The middleware reactor's cross-thread waker is a 127.0.0.1 UDP socket pair, and
 * lwip_select waits only on lwIP sockets, so the wake traverses loopback. */
#define LWIP_NETIF_LOOPBACK        1
/* Static ARP entries: the backend's addStaticNeighbor (etharp_add_static_entry). */
#define ETHARP_SUPPORT_STATIC_ENTRIES 1

/* ---------- socket options the backend uses ---------- */
#define SO_REUSE                   1   /* setReuseAddr (listeners reuse TIME-WAIT ports) */
#define LWIP_SO_RCVTIMEO           1   /* setRecvTimeoutMs (bounded recv loops) */
#define LWIP_SO_SNDTIMEO           1   /* bounded sends into a stalled peer */

/* ---------- TCP ---------- */
/* Ethernet MTU 1500 - 40 B headers: MSS announced from a 1500-MTU interface. */
#define TCP_MSS                    1460
#define TCP_SND_BUF                (8 * TCP_MSS)
#define TCP_SND_QUEUELEN           (4 * TCP_SND_BUF / TCP_MSS)
#define TCP_WND                    (8 * TCP_MSS)
/* RFC 6528 ISN randomisation is intentionally NOT configured here: the generator is
 * a product concern, not shared infrastructure, and each product owns a DIFFERENT
 * one. The conformance DUT (lwipopts.h) wires the lwIP-contrib tcp_isn addon (whose
 * wire behaviour the TC8 ratchet pins); the UTM (utm/lwipopts.h) wires a tc8-owned
 * AES-CMAC generator with no contrib/PPP/MD5 dependency. Defining the hook here
 * would force one product's generator — and its build tail — on the other, and on
 * every SDK consumer, so this base stays self-contained (pure #defines, no external
 * hook file). The seed for whichever generator a product picks is handed to the
 * common bring-up via the tc8_lwip_isn.h seam. */

/* ---------- memory sizing ---------- */
#define MEM_ALIGNMENT              4
#define MEM_SIZE                   (64 * 1024)
#define PBUF_POOL_SIZE             120
#define MEMP_NUM_TCP_PCB           8
#define MEMP_NUM_TCP_PCB_LISTEN    8
#define MEMP_NUM_TCP_SEG           64
/* Socket/netconn pool — the lwIP default of 4 exhausts immediately on a
 * persistent endpoint (RPC socket + a listen+accepted pair + an active slot). */
#define MEMP_NUM_NETCONN           16
/* UDP pcb pool — generous for the testability UDP surface + a middleware module. */
#define MEMP_NUM_UDP_PCB           16

#endif /* TC8_LWIP_LWIPOPTS_BASE_H */
