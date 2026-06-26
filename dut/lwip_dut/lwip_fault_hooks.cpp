#include "lwip_fault_hooks.h"

#include "lwip/netif.h"
#include "lwip/tcpip.h"

#include "lwip_egress_fault.h"
#include "lwip_ingress_fault.h"

namespace tc8::lwip_dut {

void installFaultHooks() {
    LOCK_TCPIP_CORE();
    // Wrap the tap link-output with the egress field-fault hook (inert until an
    // OpSetEgressFlavor sets a non-None flavor).
    installEgressFaultHook(netif_default);
    // Wrap the tap input with the ingress reaction-fault hook (inert until an
    // OpSetIngressFlavor sets a non-None flavor). After the egress hook — the ARP
    // flavor's synthesized Reply is sent via netif->linkoutput, which the egress
    // hook leaves untouched while no egress flavor is armed.
    installIngressFaultHook(netif_default);
    UNLOCK_TCPIP_CORE();
}

}  // namespace tc8::lwip_dut
