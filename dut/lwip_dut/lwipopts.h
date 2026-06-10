/* lwIP configuration for the tc8-harness lwIP DUT fixture.
 *
 * Purpose-built (not a copy of contrib/examples/example_app/lwipopts.h):
 * every deviation from lwIP defaults is either a unix-port threading
 * requirement or a documented TC8 alignment. Options absent here keep
 * their src/include/lwip/opt.h defaults on purpose — notably
 * LWIP_BROADCAST_PING=0 / LWIP_MULTICAST_PING=0 (broadcast Echo silence
 * per ICMPv4_TYPE_04/_05) and IP_REASS_CHECK_OVERLAP=1 (see
 * dut/lwip_dut/README.md for the IPv4_REASSEMBLY_13 discussion).
 */
#ifndef TC8_LWIP_DUT_LWIPOPTS_H
#define TC8_LWIP_DUT_LWIPOPTS_H

/* ---------- platform / threading (unix port, threaded stack) ---------- */
#define NO_SYS                     0
#define LWIP_SOCKET                1
#define LWIP_NETCONN               1
#define LWIP_NETIF_API             1
#define LWIP_TCPIP_CORE_LOCKING    1
/* The UT server and connector workers are plain application threads;
 * they reach the stack through the socket API only. */

/* ---------- protocol surface ---------- */
#define LWIP_IPV4                  1
/* TC8 v3.0 is an IPv4 test suite; disabling IPv6 keeps the DUT silent
 * on the wire except for behaviour the spec exercises. */
#define LWIP_IPV6                  0
#define LWIP_ICMP                  1
#define LWIP_UDP                   1
#define LWIP_TCP                   1
#define LWIP_ARP                   1
/* No IGMP/DNS/SNMP/mDNS/DHCP/AUTOIP: nothing in the swept TC8 areas
 * needs them, and a quiet DUT keeps per-case pcaps reviewable. DHCP and
 * AUTOIP become build-time opt-ins when their UT opcodes are ported. */

/* ---------- TC8 alignments (each entry cites its case) ---------- */
/* The harness fixes <ipIniReassembleTimeout> at 3 s (mirroring the
 * Linux reference DUT's per-case ipfrag_time=3 conditioning). lwIP's
 * ip_reass_tmr() ticks once per second and an entry survives
 * (MAXAGE, MAXAGE+1] s depending on tick phase, so MAXAGE=2 bounds the
 * bucket lifetime to <= 3 s (IPv4_REASSEMBLY_10 phase B probes at
 * ~3.03 s) while keeping the 1 s phase-A window valid. Trade-off: the
 * static timer cannot also satisfy IPv4_REASSEMBLY_11's TTL extension
 * (platform_known_fail, dut/lwip_dut/inventory_overrides.json). */
#define IP_REASSEMBLY              1
#define IP_FRAG                    1
#define IP_REASS_MAXAGE            2

/* OpAbortTcpSocket (0x09) implements the spec ABORT primitive as
 * SO_LINGER{on, 0} + close => RST, same recipe as the Linux tc8-dut. */
#define LWIP_SO_LINGER             1
/* OpReceiveTcpData (0x07) bounds its recv loop with SO_RCVTIMEO. */
#define LWIP_SO_RCVTIMEO           1
/* Case stimuli reuse well-known listen ports (e.g. 12345) back to back
 * while the previous case's connection sits in TIME-WAIT (2*MSL); the
 * UT server sets SO_REUSEADDR on every listener and lwIP only honours
 * it when compiled with SO_REUSE. */
#define SO_REUSE                   1
/* The fixture DUT is persistent: a data send into a stalled connection
 * (tester deliberately not ACKing) must time out and report
 * kStatusSendFailed instead of freezing the UT server for every
 * subsequent case. */
#define LWIP_SO_SNDTIMEO           1

/* Ethernet MTU 1500 - 40 B headers: keeps the DUT's MSS announcement at
 * the value TCP_MSS_OPTIONS cases expect from a 1500-MTU interface. */
#define TCP_MSS                    1460
/* RFC 6298 §2.1: initial RTO SHOULD be 1 second. lwIP's 3 s default
 * pushes the first SYN/data retransmission outside the observation
 * windows of TCP_RETRANSMISSION_TO_05/_06 (tuned to RFC-conformant
 * 1 s initial RTO); 1000 ms is the more-conformant value, not a test
 * accommodation. */
#define LWIP_TCP_RTO_TIME          1000
/* TIME-WAIT = 2*MSL. The TC8 harness (and Linux, TCP_TIMEWAIT_LEN)
 * model a 30 s MSL => 60 s TIME-WAIT; lwIP's 60 s MSL default keeps
 * TCP_BASICS_11/_12's post-2MSL probe inside a still-armed TIME-WAIT. */
#define TCP_MSL                    30000UL
/* RFC 7323 timestamps. Multi-phase cases close a connection and open
 * the next phase's on an adjacent port quad seconds later; the tester
 * kernel's TIME-WAIT socket only reopens deterministically for a SYN
 * carrying a fresh timestamp (seq-only comparison against a random ISN
 * is a coin flip). The Linux reference DUT runs with timestamps on. */
#define LWIP_TCP_TIMESTAMPS        1
/* RFC 6528 ISN randomisation via the contrib tcp_isn addon (seeded in
 * main with a getrandom secret). lwIP's default ISN is a near-constant
 * tick counter; on a fixture where port quads recur across cases the
 * predictable ISN keeps colliding with tester-side TIME-WAIT remnants
 * (a SYN with a not-greater ISN is silently dropped per RFC 6191
 * timestamp/ISN reopening rules), and it is a security non-conformance
 * in its own right. */
#define LWIP_HOOK_TCP_ISN          lwip_hook_tcp_isn
#define LWIP_HOOK_FILENAME         "tc8_lwip_hooks.h"
/* OpSendTcpDataPattern (0x0A) queues up to kMaxPatternBytes in chunks;
 * the send buffer must hold at least a few full-size segments so the
 * first DUT-emitted data segment is MSS-bounded, not buffer-bounded. */
#define TCP_SND_BUF                (8 * TCP_MSS)
#define TCP_SND_QUEUELEN           (4 * TCP_SND_BUF / TCP_MSS)
#define TCP_WND                    (8 * TCP_MSS)
#define TCP_LISTEN_BACKLOG         1

/* The fixture respawns the DUT per case, so the first UT exchange of
 * every case runs against an empty ARP cache. lwIP's default
 * ARP_QUEUEING=0 keeps only the most recent packet per pending ARP
 * entry — the UT response gets displaced by the SYN the same RPC just
 * triggered, the harness retries the open, and the retry port-shift
 * poisons the whole case. Queue them all. */
#define ARP_QUEUEING               1

/* ---------- memory sizing ---------- */
#define MEM_ALIGNMENT              4
#define MEM_SIZE                   (64 * 1024)
#define PBUF_POOL_SIZE             120
#define MEMP_NUM_TCP_PCB           8
#define MEMP_NUM_TCP_PCB_LISTEN    8
#define MEMP_NUM_TCP_SEG           64
/* Socket/netconn pool. The lwIP default of 4 exhausts immediately on a
 * persistent DUT: the UT server's own UDP socket + a passive slot's
 * listen+accepted pair + one active slot already hit the ceiling. 16
 * gives concurrent-case headroom; the UT server additionally GCs every
 * slot and retries once when socket() still reports ENOBUFS. */
#define MEMP_NUM_NETCONN           16
/* Reassembly bucket capacity for full-MTU fragment trains
 * (IPv4_REASSEMBLY / IPv4_FRAGMENTS clusters). */
#define IP_REASS_MAX_PBUFS         64
#define MEMP_NUM_REASSDATA         8

/* ---------- diagnostics ---------- */
/* Loud assert instead of silent stack corruption; the handler lives in
 * tc8_lwip_dut.cpp and aborts after logging. */
#ifdef __cplusplus
extern "C" void tc8_lwip_platform_assert(const char *msg, int line,
                                         const char *file);
#else
void tc8_lwip_platform_assert(const char *msg, int line, const char *file);
#endif
#define LWIP_PLATFORM_ASSERT(x) tc8_lwip_platform_assert(x, __LINE__, __FILE__)

#endif /* TC8_LWIP_DUT_LWIPOPTS_H */
