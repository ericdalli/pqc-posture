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

echo
echo "hybrid groups this client can offer:"
"$BIN" list -tls-groups 2>/dev/null | grep -iE 'mlkem' | sed 's/^/  /' || \
  echo "  (none found -- check the provider configuration)"
