#pragma once

namespace tc8::lwip_dut {

// Conformance-fixture only: wrap the default netif's egress + ingress paths with
// the field-/reaction-fault hooks (both inert until an OpSet*Flavor opcode arms
// them). Call once after BringUpLwipStack(), on the main thread, before starting
// any server. Kept OUT of BringUpLwipStack so the UTM bring-up exported in
// utm-sdk-lwip carries no fault-injection code — a UTM is not a fault fixture.
//
// The install is a no-op-equivalent window after bring-up: the hooks can only be
// armed via the Upper Tester (OpSetEgressFlavor / OpSetIngressFlavor), which the
// DUT starts AFTER this call, so an inbound frame processed between bring-up and
// this install sees the same behaviour either way (no flavor can be armed yet).
void installFaultHooks();

}  // namespace tc8::lwip_dut
