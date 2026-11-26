#!/usr/bin/env bash
set -uo pipefail

cfg="${CODEX_AUTH:-$HOME/.codex/auth.json}"
if [ ! -r "$cfg" ]; then
    printf '{"error":{"message":"No Codex account found in ~/.codex. Log in with codex login first."}}\n'
    exit 0
fi

if ! command -v python3 >/dev/null 2>&1; then
    printf '{"error":{"message":"python3 is required for the Codex source but was not found on PATH."}}\n'
    exit 0
fi

dir="$(cd "$(dirname "$0")" && pwd)"
helper="$dir/fetch_codex_usage.py"

if [ ! -f "$helper" ]; then
    printf '{"error":{"message":"Codex fetch helper script missing at %s."}}' "$helper"
    exit 0
fi

CODEX_AUTH="$cfg" python3 "$helper" || printf '{"error":{"message":"Could not reach the Codex usage API."}}\n'
