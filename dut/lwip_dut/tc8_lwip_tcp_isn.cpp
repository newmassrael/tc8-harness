// RFC 6528 TCP ISN generator for the AUTOSAR Testability UTM, built on the
// vendor-neutral AES-CMAC engine (src/autosar/aes_cmac) — the same MAC primitive
// the SecOC/E2E layer composes. This is the UTM's replacement for the lwIP-contrib
// tcp_isn addon, which hashes with the PPP-bundled polarssl MD5: by owning the hook
// here, the exported UTM stack config has no dependency on lwIP-contrib, the PPP
// tree, or that MD5 build quirk — the hook the UTM's lwipopts names is satisfied
// entirely by tc8-owned, self-contained code plus the engine the UTM already links.
//
// RFC 6528: ISN = M + F(localip, localport, remoteip, remoteport, secret), where M
// is a 4-microsecond timer (so ISNs advance with time, retiring old incarnations)
// and F is a keyed pseudo-random function over the connection's four-tuple (so ISNs
// are unpredictable to off-path attackers). F here is AES-CMAC keyed by the secret:
// a keyed MAC is exactly the PRF the RFC asks for, and stronger than its reference
// MD5. The spoofing-resistance rests on the secret's strength — provisioned by the
// composition root (the bring-up's getrandom seed; an OEM supplies its own at
// deployment) via SeedTcpIsn, and never retained beyond the live generator state.

#include "tc8_lwip_isn.h"
#include "tc8_lwip_utm_hooks.h"

#include <array>
#include <cstdint>
#include <cstring>

#include "lwip/ip_addr.h"
#include "lwip/sys.h"

#include "tc8/autosar/aes_cmac.h"

namespace {

// Set once by SeedTcpIsn before the first pcb, then only read. The ISN hook fires
// under the lwIP core lock (LWIP_TCPIP_CORE_LOCKING in lwipopts_base.h), so the
// read needs no further synchronization.
std::array<std::uint8_t, 16> g_isn_secret{};

}  // namespace

namespace tc8::lwip_dut {

void SeedTcpIsn(const std::uint8_t secret[16]) {
    std::memcpy(g_isn_secret.data(), secret, g_isn_secret.size());
}

}  // namespace tc8::lwip_dut

// C linkage: named by the UTM lwipopts' LWIP_HOOK_TCP_ISN and called from the lwIP
// C core. The four-tuple is serialized exactly as the RFC 6528 reference does — IPv4
// addresses as IPv4-mapped IPv6 so the v4/v6 ISN spaces stay disjoint, ports
// big-endian — and fed to AES-CMAC keyed by the secret; the low 32 bits of the tag
// are the keyed term. This build is IPv4-only (LWIP_IPV6 = 0 in lwipopts_base.h),
// so only the v4 serialization is needed. aesCmac throws only on a wrong key length;
// the key is a fixed 16-byte array, so that path is unreachable and no exception can
// escape into the C core.
extern "C" u32_t tc8_lwip_hook_tcp_isn(const ip_addr_t *local_ip, u16_t local_port,
                                       const ip_addr_t *remote_ip, u16_t remote_port) {
    std::uint8_t msg[36];
    std::memset(msg, 0, sizeof(msg));

    const ip4_addr_t *local4 = ip_2_ip4(local_ip);
    const ip4_addr_t *remote4 = ip_2_ip4(remote_ip);

    // local + remote as IPv4-mapped IPv6 (::ffff:a.b.c.d) in msg[0..15] / msg[16..31].
    msg[10] = 0xff;
    msg[11] = 0xff;
    std::memcpy(&msg[12], &local4->addr, 4);
    msg[26] = 0xff;
    msg[27] = 0xff;
    std::memcpy(&msg[28], &remote4->addr, 4);

    // Ports big-endian in msg[32..35].
    msg[32] = static_cast<std::uint8_t>(local_port >> 8);
    msg[33] = static_cast<std::uint8_t>(local_port & 0xff);
    msg[34] = static_cast<std::uint8_t>(remote_port >> 8);
    msg[35] = static_cast<std::uint8_t>(remote_port & 0xff);

    const std::array<std::uint8_t, 16> tag =
        tc8::crypto::aesCmac(g_isn_secret.data(), g_isn_secret.size(), msg, sizeof(msg));

    std::uint32_t keyed;
    std::memcpy(&keyed, tag.data(), sizeof(keyed));

    // RFC 6528 timer term: uptime in 4-microsecond units (sys_now() is milliseconds,
    // so * 250). Boot-time base is 0, matching the bring-up's seed.
    return keyed + sys_now() * 250u;
}
