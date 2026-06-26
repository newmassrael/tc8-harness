/* lwIP configuration for the standalone AUTOSAR Testability UTM (tc8-lwip-utm),
 * and the reference config shipped in the utm-sdk-lwip component.
 *
 * Layered on the product-neutral lwipopts_base.h (the infrastructure both lwIP
 * binaries share — single source of truth), adding ONLY the UTM's delta: IPv4
 * multicast, so a middleware module can join/leave groups via the backend. It
 * does NOT include the conformance DUT's config, so it inherits none of the
 * per-case wire tuning, and it leaves LWIP_PLATFORM_ASSERT at lwIP's default (the
 * loud+fatal custom sink is a conformance-verdict concern) — so the UTM has no
 * dependency on a fixture symbol and a replaced bring-up cannot break the link.
 */
#ifndef TC8_LWIP_UTM_LWIPOPTS_H
#define TC8_LWIP_UTM_LWIPOPTS_H

#include "../lwipopts_base.h"

/* IPv4 multicast — the reason an OEM UTM links its own core: a middleware module
 * joins/leaves groups via the backend (joinMulticast / leaveMulticast,
 * lwip_socket_backend.cpp), which needs IGMP + the multicast TX socket options.
 * Enabling LWIP_IGMP changes struct netif's layout, so the UTM links a separate
 * core (lwipcore_utm) and never mixes TUs with the conformance core. */
#define LWIP_IGMP                  1
#define LWIP_MULTICAST_TX_OPTIONS  1

/* RFC 6528 ISN via the tc8-owned AES-CMAC generator (tc8_lwip_tcp_isn.cpp), keyed
 * by the bring-up's secret. Deliberately NOT the lwIP-contrib tcp_isn addon the
 * conformance DUT uses: this generator reuses the AUTOSAR AES-CMAC engine the UTM
 * already links and has no lwIP-contrib / PPP / MD5 dependency, so the exported UTM
 * stack config builds from tc8-owned sources plus the OEM's lwIP checkout alone. */
#define LWIP_HOOK_TCP_ISN          tc8_lwip_hook_tcp_isn
#define LWIP_HOOK_FILENAME         "tc8_lwip_utm_hooks.h"

#endif /* TC8_LWIP_UTM_LWIPOPTS_H */
