#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace tc8::dut {

// The SOME/IP-SD multicast group this DUT's vsomeip discovers on, for the parts of
// tc8-dut that send SD around vsomeip (the client-mode FindService runner).
//
// WHY THIS EXISTS
// ---------------
// vsomeip takes the group from its configuration (`service-discovery.multicast`), and a
// site's DUT configuration may name another group than the reference one. The raw
// client-mode sender used the compiled `kSdMcastGroup`, so on such a DUT its Finds left
// on a group the DUT's own vsomeip, and the tester, were not on. Reading the same key
// from the same file keeps the two senders of one DUT on one group.
//
// WHICH FILE
// ----------
// The one the launcher hands vsomeip: `VSOMEIP_CONFIGURATION`, a file or a folder of
// `*.json` files (read in name order; the first that names the group wins, as vsomeip
// keeps the first definition it loads and warns about the rest). Every tc8 launcher
// (the orchestrator's local, ssh-remote and fixture paths) sets it. vsomeip's other
// sources (an application-named variable, a local or built-in default path) are not
// followed: their locations are fixed when vsomeip is built, so a copy here would
// guess. Without the variable, or without the key, the compiled `kSdMcastGroup`
// applies, which is the group the in-tree configurations name.
//
// Parsed with Boost.PropertyTree, the parser vsomeip itself reads its configuration
// with, so a file vsomeip accepts is read the same way here.

// The group, and where it came from for the one log line that reports it.
struct VsomeipSdGroup {
    std::uint32_t group_be = 0;  // network byte order; never 0
    std::string dotted;          // the same group as text
    std::string source;          // the file that named it, or "compiled default"
};

// The group named by the configuration at `path` (a file or a folder), if any. A file
// that cannot be read or parsed, or a value that is not a dotted IPv4 multicast
// address, names none and is reported on stderr.
std::optional<VsomeipSdGroup> sdGroupFromVsomeipConfig(const std::string &path);

// The group for this process: from `VSOMEIP_CONFIGURATION` when it names one, else
// `kSdMcastGroup`.
VsomeipSdGroup vsomeipSdGroup();

}  // namespace tc8::dut
