#!/usr/bin/env bash
# scripts/install-hooks.sh — activate the versioned git hooks for tc8-harness.
#
# Run once per local clone:
#   ./scripts/install-hooks.sh
#
# The hooks are tracked in .githooks/ (so every clone shares the same gate);
# this script just points git at them via core.hooksPath and cleans up any
# stale per-clone copies from the pre-migration .git/hooks/ location.
#
#   pre-commit / pre-push : mnemosyne-cli validate-workspace + validate-code-refs
#                           (per-commit feedback + final guard before the
#                            shared remote, before drift breaks the mnemosyne
#                            CI workflow)
#   commit-msg            : COMMIT_FORMAT.md message validation
#
# Adoption chain: Round 273-285 substrate (Phase 1A inventory axis +
# Round 281 paren-prefix + Round 283 remove-section-impl + Round 284
# bare external-prefix + Round 285 inventory orphan_ledger).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Point git at the versioned hooks. This OVERRIDES .git/hooks/, so the hooks
# must live in .githooks/ (they do) — a copy left in .git/hooks/ is ignored.
git -C "$ROOT" config core.hooksPath .githooks
echo "core.hooksPath -> .githooks (pre-commit + pre-push + commit-msg active)"

# Remove stale per-clone hooks from the pre-migration location so they do
# not masquerade as active (core.hooksPath makes git ignore .git/hooks/).
for stale in pre-commit pre-push; do
    if [[ -e "$ROOT/.git/hooks/$stale" ]]; then
        rm -f "$ROOT/.git/hooks/$stale"
        echo "removed stale .git/hooks/$stale (superseded by .githooks/)"
    fi
done

if ! command -v mnemosyne-cli >/dev/null 2>&1; then
    echo "WARN: mnemosyne-cli not in PATH — the pre-commit/pre-push gate will" >&2
    echo "      skip until installed: cd ~/mnemosyne && cargo install --path crates/mnemosyne-cli --force" >&2
fi

echo ""
echo "Test (no commit/push yet — just runs the gate):"
echo "  .githooks/pre-commit"
echo "  .githooks/pre-push"
