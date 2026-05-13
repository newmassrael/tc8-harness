#!/usr/bin/env bash
# scripts/install-hooks.sh — install Mnemosyne pre-commit hook for tc8-harness.
#
# Run once per local clone:
#   ./scripts/install-hooks.sh
#
# The hook runs `mnemosyne-cli validate-workspace` + `verify-generated` +
# `validate-code-refs` before every commit. Failures block the commit so
# stale section/inventory citations + drifted GENERATED.md don't enter
# git history.
#
# Adoption chain: Round 273-285 substrate (Phase 1A inventory axis +
# Round 281 paren-prefix + Round 283 remove-section-impl + Round 284
# bare external-prefix + Round 285 inventory orphan_ledger).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HOOK_DST="$ROOT/.git/hooks/pre-commit"

if ! command -v mnemosyne-cli >/dev/null 2>&1; then
    echo "ERROR: mnemosyne-cli not in PATH. Install:"
    echo "  cd ~/mnemosyne && cargo install --path crates/mnemosyne-cli --force"
    exit 1
fi

cat > "$HOOK_DST" <<'EOF'
#!/usr/bin/env bash
# Auto-installed by scripts/install-hooks.sh (Mnemosyne pre-commit gate).
# To bypass for genuine emergencies: git commit --no-verify
# (Do not use as workflow — fix the underlying drift instead.)

set -e

if ! command -v mnemosyne-cli >/dev/null 2>&1; then
    echo "pre-commit: mnemosyne-cli not in PATH; skipping Mnemosyne gate." >&2
    echo "pre-commit: install via ~/mnemosyne ; cargo install --path crates/mnemosyne-cli --force" >&2
    exit 0
fi

echo "pre-commit: mnemosyne-cli validate-workspace ..."
mnemosyne-cli validate-workspace

echo "pre-commit: mnemosyne-cli verify-generated ..."
mnemosyne-cli verify-generated

echo "pre-commit: mnemosyne-cli validate-code-refs ..."
mnemosyne-cli validate-code-refs

echo "pre-commit: Mnemosyne gate passed."
EOF

chmod +x "$HOOK_DST"
echo "Installed pre-commit hook at: $HOOK_DST"
echo ""
echo "Test (no commit yet — just runs the gate):"
echo "  bash .git/hooks/pre-commit"
