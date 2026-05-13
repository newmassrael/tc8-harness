#!/usr/bin/env bash
# scripts/install-hooks.sh — install Mnemosyne pre-commit + pre-push hooks
# for tc8-harness.
#
# Run once per local clone:
#   ./scripts/install-hooks.sh
#
# Both hooks run `mnemosyne-cli validate-workspace` + `verify-generated` +
# `validate-code-refs`. The pre-commit hook gives fast per-commit feedback;
# the pre-push hook catches drift introduced by --no-verify commits or
# commits made on machines without the hook installed, before it reaches
# the shared remote and breaks the mnemosyne CI workflow.
#
# Adoption chain: Round 273-285 substrate (Phase 1A inventory axis +
# Round 281 paren-prefix + Round 283 remove-section-impl + Round 284
# bare external-prefix + Round 285 inventory orphan_ledger).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PRE_COMMIT_DST="$ROOT/.git/hooks/pre-commit"
PRE_PUSH_DST="$ROOT/.git/hooks/pre-push"

if ! command -v mnemosyne-cli >/dev/null 2>&1; then
    echo "ERROR: mnemosyne-cli not in PATH. Install:"
    echo "  cd ~/mnemosyne && cargo install --path crates/mnemosyne-cli --force"
    exit 1
fi

cat > "$PRE_COMMIT_DST" <<'EOF'
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

chmod +x "$PRE_COMMIT_DST"

cat > "$PRE_PUSH_DST" <<'EOF'
#!/usr/bin/env bash
# Auto-installed by scripts/install-hooks.sh (Mnemosyne pre-push gate).
# Final guard before the commit reaches the shared remote — catches
# drift from --no-verify commits or commits made without the
# pre-commit hook installed. To bypass for genuine emergencies:
#   git push --no-verify
# (Do not use as workflow — fix the underlying drift instead.)

set -e

if ! command -v mnemosyne-cli >/dev/null 2>&1; then
    echo "pre-push: mnemosyne-cli not in PATH; skipping Mnemosyne gate." >&2
    echo "pre-push: install via ~/mnemosyne ; cargo install --path crates/mnemosyne-cli --force" >&2
    exit 0
fi

echo "pre-push: mnemosyne-cli validate-workspace ..."
mnemosyne-cli validate-workspace

echo "pre-push: mnemosyne-cli verify-generated ..."
mnemosyne-cli verify-generated

echo "pre-push: mnemosyne-cli validate-code-refs ..."
mnemosyne-cli validate-code-refs

echo "pre-push: Mnemosyne gate passed."
EOF

chmod +x "$PRE_PUSH_DST"

echo "Installed pre-commit hook at: $PRE_COMMIT_DST"
echo "Installed pre-push hook at:   $PRE_PUSH_DST"
echo ""
echo "Test (no commit/push yet — just runs the gate):"
echo "  bash .git/hooks/pre-commit"
echo "  bash .git/hooks/pre-push"
