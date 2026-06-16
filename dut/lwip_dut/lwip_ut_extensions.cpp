#include "lwip_ut_extensions.h"

#include <cstddef>
#include <cstdint>
#include <vector>

#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "lwip/tcpip.h"

#include "tc8/upper_tester_protocol.h"

namespace tc8::lwip_dut {
namespace {

namespace ut = ::tc8::ut;

}  // namespace

void registerLwipUtExtensions(tc8::ut::UpperTesterServer &server) {
    server.registerOpcode(
        ut::OpConditionArpCache,
        [](const std::uint8_t *params, std::size_t len, std::uint8_t &status,
           std::vector<std::uint8_t> & /*body*/) {
            // Params: <action:u8> <param:u16>. §4.2.4.2 ARP_48/49 cache
            // conditioning against the stack's own table — lwIP's ARP_MAXAGE is a
            // compile-time constant, so the spec's "set a timeout" / "wait for the
            // cache to refresh" steps are rendered by driving the aging machinery
            // directly. The OpConditionArpCache ACK egress is itself sent AFTER
            // the conditioning ran: when AgeBySeconds expired the requester's own
            // entry, the egress finds an empty table and lwIP emits the ARP
            // Request the ARP_48/49 step-11/15 pass criteria observe (RFC
            // 826-conformant) — deliberate, not a quirk.
            if (len < 1 + 2) {
                status = ut::kStatusMalformed;
                return;
            }
            const std::uint8_t action = params[0];
            const std::uint16_t param = ut::readU16(params + 1);
            if (action == ut::kArpConditionFlushAll) {
                // ARP_48/49 step 1 "clear the dynamic entries". Per-case DUT
                // respawn already yields a cold table; this is the
                // persistent-fixture rendering. `param` is ignored.
                LOCK_TCPIP_CORE();
                etharp_cleanup_netif(netif_default);
                UNLOCK_TCPIP_CORE();
            } else if (action == ut::kArpConditionAgeBySeconds) {
                // Compress the step-8/12 <DYNAMIC-ARP-CACHE-TIMEOUT> wait: one
                // etharp_tmr() call advances every entry's ctime by one
                // ARP_TMR_INTERVAL (1 s) tick — `param` calls age the table by
                // `param` seconds of virtual time through the exact code path
                // wall-clock aging takes (entries crossing ARP_MAXAGE are freed by
                // etharp_tmr itself).
                LOCK_TCPIP_CORE();
                for (std::uint16_t i = 0; i < param; ++i) {
                    etharp_tmr();
                }
                UNLOCK_TCPIP_CORE();
            } else {
                // No compliant fallback for an unknown conditioning — a silent
                // no-op would run the case against an unconditioned cache and time
                // out with a misleading verdict.
                status = ut::kStatusMalformed;
                return;
            }
            status = ut::kStatusOk;
        });
}

}  // namespace tc8::lwip_dut
