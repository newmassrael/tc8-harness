/* lwIP configuration for the tc8-lwip-utm middleware UTM binary.
 *
 * The conformance DUT (tc8-lwip-dut) and the UTM share one lwIP checkout but
 * NOT one config. This file is the UTM's, layered on the conformance base so the
 * two never drift on the options they agree about. It turns ON IPv4 multicast
 * (LWIP_IGMP) and the multicast TX socket options — the network-management
 * capability an out-of-tree UTM module needs (joinMulticast / leaveMulticast,
 * lwip_socket_backend.cpp) — which the conformance base deliberately leaves OFF
 * to keep its wire behaviour silent on the broadcast/multicast discard cases
 * (UDP_INTRODUCTION_02 et al.).
 *
 * Enabling LWIP_IGMP changes struct layouts (struct netif gains igmp_mac_filter),
 * so the UTM links its OWN lwIP core built against this file (lwipcore_utm /
 * lwipcontribportunix_utm in CMakeLists.txt) and never mixes translation units
 * with the conformance core. The conformance core stays exactly as it was, so
 * tc8-lwip-dut's wire behaviour is unchanged.
 *
 * Layering: pre-define the multicast opts, then include the conformance base
 * (a relative path, not the bare-name include the UTM core resolves to this
 * directory). The base does not touch LWIP_IGMP, so these survive into opt.h's
 * defaulting.
 */
#ifndef TC8_LWIP_UTM_LWIPOPTS_H
#define TC8_LWIP_UTM_LWIPOPTS_H

#define LWIP_IGMP                  1
#define LWIP_MULTICAST_TX_OPTIONS  1

#include "../lwipopts.h"

/* The layering above relies on the conformance base NOT defining LWIP_IGMP (it
 * only omits it, letting opt.h default it to 0 there). Enforce that invariant in
 * code, not by trusting a comment: if a future edit makes the base predefine the
 * symbol, this fails the build loudly instead of silently disabling multicast in
 * the UTM (which would make joinMulticast quietly return rejection with no signal). */
#if LWIP_IGMP != 1
#error "base lwipopts.h must not predefine LWIP_IGMP; the UTM layer owns it"
#endif

#endif /* TC8_LWIP_UTM_LWIPOPTS_H */
