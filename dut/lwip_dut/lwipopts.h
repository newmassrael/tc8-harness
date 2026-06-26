/* lwIP configuration for the tc8-harness lwIP DUT fixture (tc8-lwip-dut).
 *
 * The product-neutral infrastructure both lwIP binaries share lives in
 * lwipopts_base.h; this file #includes it and adds ONLY the conformance-fixture
 * delta — per-case wire tuning (each entry cites its TC8 case) and the loud assert
 * sink — so the UTM config never inherits any of it. Options absent here keep
 * their src/include/lwip/opt.h defaults on purpose — notably LWIP_BROADCAST_PING=0
 * / LWIP_MULTICAST_PING=0 (broadcast Echo silence per ICMPv4_TYPE_04/_05) and
 * IP_REASS_CHECK_OVERLAP=1 (see dut/lwip_dut/README.md for the IPv4_REASSEMBLY_13
 * discussion).
 */
#ifndef TC8_LWIP_DUT_LWIPOPTS_H
#define TC8_LWIP_DUT_LWIPOPTS_H

#include "lwipopts_base.h"

/* RFC 6528 ISN via the lwIP-contrib tcp_isn addon (tc8_lwip_hooks.h pulls its
 * header onto the include path; the addon + the PPP-polarssl MD5 it hashes with are
 * compiled into tc8-lwip-dut by dut/lwip_dut/CMakeLists.txt). This is the
 * conformance generator whose wire behaviour the TC8 ratchet pins, so it stays as
 * is — the move out of lwipopts_base.h is config-location only, not a behaviour
 * change. The UTM uses a tc8-owned AES-CMAC generator instead (utm/lwipopts.h). The
 * seed is delivered through the tc8_lwip_isn.h seam (tc8_lwip_dut.cpp). */
#define LWIP_HOOK_TCP_ISN          lwip_hook_tcp_isn
#define LWIP_HOOK_FILENAME         "tc8_lwip_hooks.h"

/* The §4.4.4.5 ADDRESSING data listener (OpGetReceivedUdp) must recover each
 * datagram's ORIGINAL wire destination to apply the RFC 1122 directed-broadcast
 * / multicast silent-discard (ADDRESSING_02 / UDP_INTRODUCTION_02). This appends
 * the destination addr+port to every received netbuf, surfaced to the UT core's
 * StackProbe via recvmsg + IP_PKTINFO — the socket-layer equivalent of the Linux
 * DUT's IP_PKTINFO ancillary path. Additive and gated; no other behaviour
 * changes. See dut/lwip_dut/lwip_stack_probe.cpp recvWithOriginalDstV4(). */
#define LWIP_NETBUF_RECVINFO       1

/* ---------- TC8 alignments (each entry cites its case) ---------- */
/* The harness fixes <ipIniReassembleTimeout> at 3 s (mirroring the Linux
 * reference DUT's per-case ipfrag_time=3 conditioning). lwIP's ip_reass_tmr()
 * ticks once per second and an entry survives (MAXAGE, MAXAGE+1] s depending on
 * tick phase, so MAXAGE=2 bounds the bucket lifetime to <= 3 s (IPv4_REASSEMBLY_10
 * phase B probes at ~3.03 s) while keeping the 1 s phase-A window valid. Trade-off:
 * the static timer cannot also satisfy IPv4_REASSEMBLY_11's TTL extension
 * (platform_known_fail, dut/lwip_dut/inventory_overrides.json). The generic
 * IP_REASSEMBLY/IP_FRAG enable lives in lwipopts_base.h. */
#define IP_REASS_MAXAGE            2
/* Reassembly bucket capacity for full-MTU fragment trains
 * (IPv4_REASSEMBLY / IPv4_FRAGMENTS clusters). */
#define IP_REASS_MAX_PBUFS         64
#define MEMP_NUM_REASSDATA         8

/* OpAbortTcpSocket (0x09) implements the spec ABORT primitive as
 * SO_LINGER{on, 0} + close => RST, same recipe as the Linux tc8-dut. (The UTM's
 * lwIP backend aborts via tcp_abort instead, so this is DUT-only.) */
#define LWIP_SO_LINGER             1

/* RFC 6298 §2.1: initial RTO SHOULD be 1 second. lwIP's 3 s default pushes the
 * first SYN/data retransmission outside the observation windows of
 * TCP_RETRANSMISSION_TO_05/_06; 1000 ms is the more-conformant value. */
#define LWIP_TCP_RTO_TIME          1000
/* TIME-WAIT = 2*MSL. The TC8 harness (and Linux, TCP_TIMEWAIT_LEN) model a 30 s
 * MSL => 60 s TIME-WAIT; this keeps TCP_BASICS_11/_12's post-2MSL probe inside a
 * still-armed TIME-WAIT. */
#define TCP_MSL                    30000UL
/* RFC 7323 timestamps. Multi-phase cases reopen an adjacent port quad seconds
 * later; the tester kernel's TIME-WAIT socket only reopens deterministically for
 * a SYN carrying a fresh timestamp. The Linux reference DUT runs timestamps on. */
#define LWIP_TCP_TIMESTAMPS        1
/* OpSendTcpDataPattern (0x0A): bound the listen backlog. */
#define TCP_LISTEN_BACKLOG         1

/* The fixture respawns the DUT per case, so the first UT exchange of every case
 * runs against an empty ARP cache. lwIP's default ARP_QUEUEING=0 keeps only the
 * most recent packet per pending entry — the UT response gets displaced by the
 * SYN the same RPC just triggered. Queue them all. */
#define ARP_QUEUEING               1

/* The §4.2.4.2 drop-and-emit `_NEG` track (ARP_22/28/38) relies on the static-ARP
 * capability (ETHARP_SUPPORT_STATIC_ENTRIES, enabled in lwipopts_base.h): the
 * ingress fault hook injects a static entry (lwip_ingress_fault.cpp,
 * kArpFaultLearnFromDropFrame) to model a buggy DUT that wrongly learned the
 * dropped Response's address. No positive case uses static entries, so the
 * capability does not alter conformant behaviour. (Conformance rationale for the
 * base-provided option; the UTM uses the same option for addStaticNeighbor.) */

/* ---------- diagnostics ---------- */
/* Loud assert instead of silent stack corruption: a tripped invariant makes every
 * verdict after it untrustworthy. A conformance concern, so it is the DUT's; the
 * handler is defined in tc8_lwip_dut.cpp and aborts after logging. The UTM uses
 * lwIP's default assert and never references this symbol. */
#ifdef __cplusplus
extern "C" void tc8_lwip_platform_assert(const char *msg, int line,
                                         const char *file);
#else
void tc8_lwip_platform_assert(const char *msg, int line, const char *file);
#endif
/* lwip/arch.h carries an #ifndef-guarded default; #undef before redefining keeps
 * the substitution ours without a -Wbuiltin-macro-redefined / "redefined" warning. */
#undef LWIP_PLATFORM_ASSERT
#define LWIP_PLATFORM_ASSERT(x) tc8_lwip_platform_assert(x, __LINE__, __FILE__)

#endif /* TC8_LWIP_DUT_LWIPOPTS_H */
