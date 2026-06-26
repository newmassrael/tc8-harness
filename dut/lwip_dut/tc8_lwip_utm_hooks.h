/* lwIP hook header for the AUTOSAR Testability UTM, named by utm/lwipopts.h via
 * LWIP_HOOK_FILENAME and #included by every lwIP core TU at its hook site.
 *
 * The hook prototype cannot live in lwipopts.h: that file is parsed before the
 * core types (ip_addr_t, u32_t) are defined, whereas the hook site includes this
 * header after them. This is the lwIP-documented idiom (the contrib tcp_isn addon
 * uses the same split).
 *
 * Declares the tc8 AES-CMAC RFC 6528 ISN hook (implemented in tc8_lwip_tcp_isn.cpp)
 * — the UTM's replacement for the lwIP-contrib tcp_isn addon, carrying no contrib /
 * PPP / MD5 dependency, so the exported UTM stack config builds from tc8-owned
 * sources plus the OEM's own lwIP checkout alone.
 */
#ifndef TC8_LWIP_UTM_HOOKS_H
#define TC8_LWIP_UTM_HOOKS_H

#include "lwip/ip_addr.h"

#ifdef __cplusplus
extern "C" {
#endif

u32_t tc8_lwip_hook_tcp_isn(const ip_addr_t *local_ip, u16_t local_port,
                            const ip_addr_t *remote_ip, u16_t remote_port);

#ifdef __cplusplus
}
#endif

#endif /* TC8_LWIP_UTM_HOOKS_H */
