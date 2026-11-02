#pragma once

#include <cstdint>
#include <optional>

namespace tc8 {

// What the operator declares about the test network. A captured frame says what the DUT
// sent; only this says what the network expects. Without it a case cannot tell an
// untagged frame on a tagged network, which is a violation, from an untagged network,
// which is correct.
//
// `vlan_id` unset means an untagged network and no expectation: a case then grades no tag.
// Set (`--expect network.vlan_id=<1..4094>`, or a site's `vlan_id`), the network is tagged
// with that identifier, and a case may hold a DUT frame to it. The harness grades nothing
// by itself: a case reads this and the tag on the frame.
struct NetworkDeclarations {
    std::optional<std::uint16_t> vlan_id;
};

}  // namespace tc8
