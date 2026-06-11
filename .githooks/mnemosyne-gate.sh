#!/usr/bin/env bash
# Shared Mnemosyne gate for the pre-commit and pre-push hooks (.githooks/).
# Runs both validators the CI mnemosyne workflow runs, so local commits and
# pushes catch drift before it reaches the shared remote:
#   - validate-workspace  : T1 cross-ref orphans + frozen-ledger + style
#   - validate-code-refs   : citation bindings (bare TC8 §-refs must bind to
#                            a section; RFC-prefixed refs are external/exempt)
#
# $1 = invoking hook name (for log prefixes). Bypass for genuine emergencies:
#   git commit --no-verify  /  git push --no-verify
# (Do not use as workflow — fix the underlying drift instead.)
set -e

hook="${1:-hook}"

if ! command -v mnemosyne-cli >/dev/null 2>&1; then
    echo "$hook: mnemosyne-cli not in PATH; skipping Mnemosyne gate." >&2
    echo "$hook: install via ~/mnemosyne ; cargo install --path crates/mnemosyne-cli --force" >&2
    exit 0
fi

echo "$hook: mnemosyne-cli validate-workspace ..."
mnemosyne-cli validate-workspace

echo "$hook: mnemosyne-cli validate-code-refs ..."
mnemosyne-cli validate-code-refs

echo "$hook: Mnemosyne gate passed."
