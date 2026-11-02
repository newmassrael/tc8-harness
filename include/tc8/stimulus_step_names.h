#pragma once

#include <string_view>

// The names of the stimulus steps a case can be told were applied
// (`Traits::onStimulusApplied`, test_case_traits.h), one definition each.
//
// A name belongs to the seam OPERATION, not to the backend that carries it: a case
// grading the static ARP entry waits for `kStepArpStaticEntryAdd` whether the opcode
// UT installed the entry or a registered extension did over the DUT's own service
// primitives. So every provider marks its acknowledgement with the constant here
// (the opcode stimulus helpers, an extension through
// IServicePrimitiveControl::callAsStep), and a case compares against the same
// constant. A provider that spelled the string itself would leave the case waiting
// for a name nobody sends, which reads as an unconfirmed install, not as a typo.

namespace tc8::step {

// IArpStaticEntry::addStaticEntry / removeStaticEntry (dut_arp_control.h names the
// specification operations they are).
inline constexpr std::string_view kArpStaticEntryAdd = "dut_arp_static_entry_add";
inline constexpr std::string_view kArpStaticEntryRemove = "dut_arp_static_entry_remove";

}  // namespace tc8::step
