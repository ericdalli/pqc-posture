#!/usr/bin/env bash
# Confirms the OpenSSL that pqc-posture will use can actually offer hybrid
# groups. Run this first on any new machine -- it is the single most common
# reason the scanner reports "no PQ support" everywhere.
set -uo pipefail

BIN="${PQC_OPENSSL:-$(command -v openssl)}"
if [[ -z "$BIN" ]]; then
  echo "FAIL: no openssl on PATH and PQC_OPENSSL is unset"
  exit 3
fi

echo "binary : $BIN"
echo "version: $("$BIN" version)"

if ! "$BIN" version | grep -qE 'OpenSSL 3\.(5|[6-9]|[1-9][0-9])'; then
  cat <<'MSG'

FAIL: this build predates OpenSSL 3.5 and cannot offer ML-KEM groups.

  Ubuntu 26.04 / Debian 13 : apt-get install openssl        (ships 3.5.x)
  macOS                    : brew install openssl@3.5
  Anything older           : build 3.5 side by side, then
                             export PQC_OPENSSL=/opt/openssl-3.5/bin/openssl

The scanner will refuse to run rather than report targets as lacking support
they may well have.
MSG
  exit 1
fi

TLS_GROUPS="$("$BIN" list -tls-groups 2>/dev/null | tr ':' '\n' | sed 's/^[[:space:]]*//')"

# 3.5 prints every group on ONE colon-separated line, so grepping the raw
# output matches the whole line and reports classical groups as hybrid.
# Split on colons first.
#
# TLS_GROUPS, not GROUPS: GROUPS is a read-only bash builtin holding your Unix
# group IDs. Assigning to it fails SILENTLY -- no error, even under set -u --
# and the variable keeps its original numeric value.
HYBRID="$(printf '%s\n' "$TLS_GROUPS" | grep -iE 'MLKEM' | grep -ivE '^MLKEM')"
PURE="$(printf '%s\n' "$TLS_GROUPS" | grep -iE '^MLKEM')"

echo
echo "hybrid groups (classical + ML-KEM) this client can offer:"
if [[ -n "$HYBRID" ]]; then
  printf '%s\n' "$HYBRID" | sed 's/^/  /'
else
  echo "  (none -- this client cannot measure post-quantum key exchange)"
fi

echo
echo "pure ML-KEM groups (no classical hedge, rarely deployed):"
if [[ -n "$PURE" ]]; then
  printf '%s\n' "$PURE" | sed 's/^/  /'
else
  echo "  (none)"
fi
