#pragma once

#include <cstdio>
#include <cstdlib>

namespace tc8::sce {

// SSOT for the dedicated iptables chain that houses every tester-side suppression
// rule the RAII scopes install. Rules NEVER go directly into a built-in hook: a
// SIGKILLed harness skips the RAII destructors, and a rule leaked into OUTPUT/INPUT
// silently poisons every later TCP exchange against the DUT on topologies whose
// tester kernel persists across runs (external / ssh-remote; single-pc discards the
// per-case netns). With one well-known chain, smoke-test.sh flushes the leaks at
// bring-up without knowing any rule shape. The hook->chain jump itself is idempotent
// permanent residue, inert while the chain is empty.
//
// This is the single home of the chain name and its create-and-jump helper — the
// name is ALSO mirrored (irreducibly) in dut/env/smoke-test.sh's bring-up flush.
inline constexpr const char *kTesterStimulusChain = "tc8-stimulus";

// Ensure the chain exists and is reached from `builtin_hook` (idempotent). A caller
// installing OUTBOUND rules passes "OUTPUT" (the default); one installing INBOUND
// rules passes "INPUT". Both jumps may coexist — the per-rule match keeps them from
// cross-matching. Returns true on success; a failure is the caller's cue to skip its
// rule non-fatally (the test then surfaces a deterministic timeout, not a hang).
inline bool ensureTesterStimulusChain(const char *builtin_hook = "OUTPUT") {
    char cmd[192];
    std::snprintf(cmd, sizeof(cmd),
                  "iptables -w 5 -nL %s >/dev/null 2>&1 || "
                  "iptables -w 5 -N %s 2>/dev/null",
                  kTesterStimulusChain, kTesterStimulusChain);
    if (std::system(cmd) != 0) {
        return false;
    }
    std::snprintf(cmd, sizeof(cmd),
                  "iptables -w 5 -C %s -j %s 2>/dev/null || "
                  "iptables -w 5 -A %s -j %s 2>/dev/null",
                  builtin_hook, kTesterStimulusChain, builtin_hook, kTesterStimulusChain);
    return std::system(cmd) == 0;
}

}  // namespace tc8::sce
