/* lwIP hook prototypes for the tc8 lwIP DUT fixture.
 *
 * Included by lwIP core TUs via LWIP_HOOK_FILENAME after the core types
 * are declared (lwipopts.h itself is parsed before ip_addr_t exists, so
 * the hook prototypes cannot live there).
 */
#ifndef TC8_LWIP_DUT_HOOKS_H
#define TC8_LWIP_DUT_HOOKS_H

/* LWIP_HOOK_TCP_ISN — RFC 6528 ISN generator (contrib/addons/tcp_isn). */
#include "tcp_isn.h"

#endif /* TC8_LWIP_DUT_HOOKS_H */
