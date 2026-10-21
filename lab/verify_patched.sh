#!/usr/bin/env bash
# Differential verification: same PoC against the vulnerable and the patched
# PHP 8.5 build.  The patched build must NOT execute the command.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
SID="abcdef0123456789abcdef0123456789"
GADGET="${GADGET:-/tmp/opencode/scratchpad/ext-pwn/modules/pwn.so}"

run_one() {
  local name="$1" phpbin="$2" port="$3" root="$4"
  if [ ! -x "$phpbin" ]; then
    echo "[$name] $phpbin not built - skipping"
    return
  fi
  mkdir -p "$root/www" "$root/sessions"
  cp "$HERE"/{index.php,consumer.php,producer.php} "$root/www/"
  sed -e "s#/tmp/asanlab/sessions#$root/sessions#" "$HERE/lab.ini" > "$root/lab.ini"
  "$phpbin" -d extension="$GADGET" -S "127.0.0.1:$port" -t "$root/www" -c "$root/lab.ini" \
      > "$root/server.log" 2>&1 &
  local pid=$!
  sleep 2
  rm -f /tmp/pwned
  echo "=== $name ($($phpbin -r 'echo PHP_VERSION;')) ==="
  python3 "$ROOT/poc_rce.py" --url "http://127.0.0.1:$port/" --sid "$SID" \
          --session-path "$root/sessions/sess_$SID" --stage both 2>&1 | sed 's/^/    /'
  if [ -f /tmp/pwned ]; then
    echo "    RESULT: command executed -> $(cat /tmp/pwned)"
  else
    echo "    RESULT: no command execution"
  fi
  kill "$pid" 2>/dev/null
  echo
}

run_one "VULNERABLE" "${PHP_BIN:-/tmp/php-vuln85/bin/php}" 9041 /tmp/poc-lab-vuln
run_one "PATCHED"   "${PHP_BIN_PATCHED:-/tmp/php-patched/bin/php}" 9042 /tmp/poc-lab-patched
