# Vulnerability & Exploit Detail — CVE-2026-109618 / CVE-2026-109619 (PHP critical RCE)

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

For authorized red-team customers only. This document explains what the
vulnerabilities are, why they exist, how the exploit kit works, how to
reproduce them, and how to mitigate. It is paired with `GUIDE.md` (step-by-step
lab reproduction) and `README.md` (PoC inventory and usage).

---

## 1. Executive summary

A request-startup path in PHP unserialises attacker-controlled session data
**before any application code runs**. Combined with two upstream state-corruption
bugs (one logical, one memory-corruption), this gives **unauthenticated remote
code execution with the privileges of the PHP worker**.

| CVE | GHSA | Title | Fix commit |
|---|---|---|---|
| CVE-2026-109618 | GHSA-w8hw-w9fx-j79w | RCE via OOM corruption | php-src `3584a98b` |
| CVE-2026-109619 | GHSA-6wmf-4rv5-p3rp | RCE via stale global state | php-src `3584a98b` |

- **Impact:** RCE as the web worker. When the worker is root, that is root.
- **Authentication:** none required. The trigger is one multipart POST to any
  PHP route.
- **When it fires:** during `php_request_startup()`, before RINIT and before
  the application script. Application-level filters on the route do not help.
- **Reach:** every PHP web server since session.upload_progress existed
  (PHP ≥ 5.4) where `session.upload_progress.enabled=1` (the default).
- **Fix:** update to PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 (or a vendor
  backport of `3584a98b`). That is the only complete fix.

The two CVEs are two aspects of one story:

1. **CVE-2026-109618** is the memory-corruption half. An OOM during request
   parsing used `bailout()` (longjmp), which left request state inconsistent.
   That state is then consumed by the shutdown path.
2. **CVE-2026-109619** is the logical half. Request-owned globals
   (`BG(unserialize)`, session state) survived into the next request, and the
   session upload-progress handler consumes that stale state before RINIT.

The **exploitable surface** for both is the same: the session upload-progress
handler. That is the consumer that turns either bug into code execution.

---

## 2. The public-facing truth about the trigger

There is a widely-distributed public narrative that CVE-2026-109618 is a heap
corruption that directly plants a forged `zend_fcall_info` and calls
`zend_call_function → system()` from a single request. Independent public
reproduction of that pipeline in the lab was **not achieved** at the time of
writing for every build. What was reproduced, deterministically, in the lab is
the **session-poisoning path**: an attacker who can place bytes in the session
store triggers unserialize() at request startup, and a gadget class's
`__wakeup()` / `__destruct()` runs.

The two are not in conflict. They are different exploit strategies against the
same root cause:

- **Session poisoning** is reliable, logical, and reproduced. It needs an
  attacker-controlled session primitive (any place the app writes user input into
  `$_SESSION`, or direct session-file access during an assessment). It does not
  need a memory leak.
- **Memory corruption** (heap groom → reclaim → forged `zend_fcall_info`) is
  the gadget-class-free, in-memory path. It is build-specific: the heap geometry
  and the `zend_call_function` / `zval_ptr_dtor` runtime address matter. The
  kit ships `symextract.py` to extract those symbols from the target binary, and
  `poc_rce.py --mode corrupt` to build and send the body. That path is provided
  as evidence of the upstream CVSS basis and as a weaponization harness for the
  specific target build you are assessing — it is not claimed to work universally.

A responsible red-team delivery presents both, and is explicit about which one
was reproduced against the specific target. This document does that.

---

## 3. Root cause — CVE-2026-109619 (stale global state)

### 3.1 What the session upload-progress handler does

When `session.upload_progress.enabled=1` (the PHP default), PHP hooks into the
multipart parser (`rfc1867`). For every file field in a multipart request it:

1. opens / resumes the session identified by `PHPSESSID` (from the cookie **or**
   from a `PHPSESSID` form field — the latter works even with
   `session.use_only_cookies=1`, see `session.c:3261-3263`),
2. stores progress information under the key `upload_progress_<value>` where
   `<value>` is the `PHP_SESSION_UPLOAD_PROGRESS` form field,
3. reads back the session on later callbacks.

Crucially, this happens during **request startup** (`sapi_activate()` →
`php_request_startup()`), i.e. before `RINIT` and before the application
script runs. So anything that happens during session load happens before the
application can defend itself.

### 3.2 The stale-pointer primitive

`ext/standard/var_unserializer.re` (pre-patch):

```c
PHPAPI php_unserialize_data_t php_var_unserialize_init(void) {
    if (BG(serialize_lock) || !BG(unserialize).level) {
        d = emalloc(sizeof(struct php_unserialize_data));
        ...
        BG(unserialize).data = d;
        BG(unserialize).level = 1;
    } else {
        d = BG(unserialize).data;      /* <-- reuses a pointer from a previous request */
        ++BG(unserialize).level;
    }
    return d;
}
```

`BG(unserialize)` is a worker global. If a request initialises the unserializer
(`PHP_VAR_UNSERIALIZE_INIT`) and then exits **without** calling
`PHP_VAR_UNSERIALIZE_DESTROY` — because of an OOM `bailout()`, a fatal error, a
parse error — then `BG(unserialize).data` keeps pointing into memory that is
freed when the request ends.

The **next** request that unserialises something *before RINIT* — i.e. the
session upload-progress handler — calls `php_var_unserialize_init()`, sees
`level != 0`, and reuses the dangling pointer. The unserializer then writes
through it (`var_push_dtor()` → `(*var_hashx)->last_dtor->next = var_hash;`).
That is use-after-free.

The patch adds `php_basic_early_rinit()` (called from `php_request_startup()`
**before** any request data is processed) which zeroes `BG(serialize)` /
`BG(unserialize)`:

```c
PHPAPI void php_basic_early_rinit(void)
{
    BG(serialize_lock) = 0;
    memset(&BG(serialize), 0, sizeof(BG(serialize)));
    memset(&BG(unserialize), 0, sizeof(BG(unserialize)));
    php_url_scanner_early_rinit();
}
```

So on the patched build, `level` is 0 at the start of every request, and the
stale-pointer branch is never taken.

### 3.3 The application primitive that turns unserialize into RCE

Unserializing at request startup is not, by itself, code execution. It becomes
RCE when the session contains a serialized object whose class defines a dangerous
`__wakeup()` or `__destruct()`. PHP will instantiate the object and call the
magic method during the unserialize.

This is exactly the same primitive as the classic PHP session-injection attacks.
The difference here is **when** it runs: before any application code, so
application-level mitigations on the request path are irrelevant.

Real applications expose such gadget classes through frameworks and extensions.
The lab uses a minimal 20-line test extension (`Pwn::__wakeup()` calls
`system()`) so the PoC is self-contained; the extension is not the vulnerability,
it is the observable proxy for any real gadget class.

---

## 4. Root cause — CVE-2026-109618 (OOM corruption)

### 4.1 The bailout-on-OOM path

Pre-patch, PHP used `bailout()` (a `longjmp`) for out-of-memory conditions,
including inside request parsing. When the OOM happened while request data was
only partially initialised, the longjmp escaped contexts that did not account for
the early exit, leaving invalid request state that the shutdown procedure then
consumed.

The patch replaces the OOM `bailout()` with a delayed soft OOM
(`UnwindExit` at the next VM safe point) plus an immediate hard OOM (`_exit()`)
at a second, higher threshold.

### 4.2 The reachable consumer

The consumer that makes this practically reachable is again the session
upload-progress handler, because:

- `memory_limit` is a user-influencable limit (within the pool config),
- multipart parsing is memory-intensive in the right shape,
- the handler runs early enough that the corrupted state is still live.

The harness `poc.py --mode oom` and `poc.py --mode http-oom` drive this path
against FPM and mod_php respectively. The observable effect is a worker killed
during request startup (FPM child exit code 70, `Allowed memory size … exhausted`).

### 4.3 The heap-reclaim weaponization (the gadget-class-free path)

When the stale `BG(unserialize)` pointer is a HashTable bucket store, and the
next request builds a session progress HashTable of the same size class, the
freed memory can be reclaimed by attacker-shaped data. The published research
reports a 149-field packed-array reclaim where each field is a 288-byte string
(`zend_string` alloc → 320-byte bin, matching the progress arData size class),
and that reclaim is shaped into a forged `zend_fcall_info` / `zend_internal_function`
whose `handler` points at `zend_call_function` with `"system\0<cmd>\0"` planted
in the string tail. When the stale bucket store writes into that reclaimed
memory, the forged function object is consumed and `system()` is called.

The kit includes `poc_rce.py --mode corrupt` (bug variants 618/619), which
builds that body and sends it with the required two-chunk stall (so the second
`FILE_DATA` triggers the second `update()` / re-decode / `zval_ptr_dtor` cycle
that leaves the cached pointers stale). It also includes `symextract.py` to
extract the per-build `zval_ptr_dtor` and `zend_call_function` addresses (and
the delta between them) directly from the PHP binary by parsing ELF64 `.dynsym`
— no `nm`, no `readelf`, no binutils.

**Reproduction status (honest):** the arming (building the body with verified-
correct layout and runtime addresses) is reproduced. The full leak→corrupt→
system() pipeline is build- and heap-history-sensitive; the kit is the
instrument for testing a given target build, and the customer-facing claim is
that the path exists and is provided, not that it works on every build without
tuning.

---

## 5. The four exploit variants in the kit

### 5.1 Variant 1 — session poisoning (default, reproduced)

The attacker gets a serialized gadget object into the session store, then sends
one multipart request that engages the upload-progress handler. The session is
unserialized during request startup; `__wakeup()` runs; the command executes.

Two sub-paths for getting the bytes into the session store:

- **Direct file write** (`--session-path`): the assessment has a way to place
  bytes in the session directory (local access, a prior session-write primitive,
  or a misconfigured session save path). This is the cleanest, most reliable
  demonstration.
- **Filename injection**: the uploaded file's name is stored in
  `$_SESSION["upload_progress_<marker>"]`. If the application's session
  serializer accepts the `|` character (the `php_serialize` handler does),
  the serialized object can be carried in the filename and later unserialized by
  a `php`-handler read.

This is the path reproduced in the lab and shown in `GUIDE.md`.

### 5.2 Variant 2 — handler mismatch

PHP has two session serializers: `php` (the default, writes
`name|serialized-value`) and `php_serialize` (writes raw `serialize()` output).
The `php` handler **encodes** values with `php_session_encode`, which rejects
`|` in the value (session.c:1078), but it **decodes** by splitting the file on
the first `|`. The `php_serialize` handler accepts `|` in keys.

If a session is written by the `php_serialize` handler (e.g. via a `.user.ini`-
switched endpoint) with a key that contains `|`, and later read by the `php`
handler (e.g. a different endpoint with a different `.user.ini`), the file is
split on that `|` and the remainder is unserialized. So an attacker who can
write to a `php_serialize`-handled endpoint and read via a `php`-handled one can
inject an object without a direct file-write precondition.

This is the path behind `poc_rce.py --mode mismatch` and the ikow verification
scripts. It requires two docroots / `.user.ini` configurations sharing one
`session.save_path`.

### 5.3 Variant 3 — include sink (gadget-class-free, logical)

Some applications pass session data into an executable sink: `include` /
`require` of a session-derived path, `eval`, `assert`, `preg_replace` /e, etc.
In that case the attacker does not need a gadget class at all: they store PHP
code (or a path) in the session, trigger the upload-progress handler to make the
session load happen, and the application's own sink executes it.

`poc_rce.py --mode include` demonstrates the upload-progress trigger feeding a
session value; the actual execution depends on the target application having such
a sink. This variant exists to show that the surface is not limited to
`__wakeup()` gadgets.

### 5.4 Variant 4 — memory corruption (gadget-class-free, heap)

`poc_rce.py --mode corrupt` builds the two-chunk stalled body with a forged
`zend_fcall_info` blob, using the runtime `zend_call_function` address obtained
from `symextract.py`. It depends on build-specific heap geometry and is provided
as the gadget-class-free weaponization harness.

---

## 6. The untrusted-input carriers — what you can actually control

Understanding the carriers is what lets you reason about a real target.

### 6.1 The session id (`PHPSESSID`)

The session id can be supplied in the cookie **or** in a `PHPSESSID` form field.
The form-field path is processed during request startup, before script
resolution, and works even with `session.use_only_cookies=1`. This means an
attacker can fixate a session id without cookies and without authentication.

### 6.2 The upload-progress marker (`PHP_SESSION_UPLOAD_PROGRESS`)

The marker value becomes the session key `upload_progress_<marker>`. Constraints
on the marker:

- Cannot contain `|` if the writing handler is the `php` handler (encoding
  fails → write silently skipped, session.c:523-537). This is why the handler-
  mismatch path uses the `php_serialize` writer for the poisoned key.
- Cannot contain CR / LF (terminates the multipart value).
- Must not be empty (disables progress tracking).

### 6.3 The filename carrier

The uploaded file's name is stored verbatim (for the `php_serialize` handler) in
the session. This is a second carrier for attacker content — but embedded double
quotes break the Content-Disposition attribute early, so the filename carrier is
less reliable than the progress-marker carrier for structured payloads. Use the
marker carrier for the serialized object; use the filename carrier when you need
a raw string (e.g. PHP code for an include sink).

### 6.4 Session file charset (files handler)

The default `files` session save handler restricts session ids to
`[a-zA-Z0-9,-]` (mod_files.c:165). Sids outside that set may be rejected at the
path level. Keep your test SIDs in that set.

---

## 7. Why the timing matters — before application code

The single most important property for remediation is that the exploit fires
**before** the application script runs. Concretely:

- `php_request_startup()` calls the session upload-progress handler.
- `RINIT` (where `php_basic_early_rinit()` now resets the globals) comes after.
- The application script comes after RINIT.

So anything that runs during request startup — session load, upload-progress
callback — happens before the application can inspect the request, validate the
session, or decide whether to trust it. This is why WAF rules on the application
route, application input validation, and `ini_set()` calls in the application
are not effective here.

---

## 8. How to reproduce (summary)

Full steps are in `GUIDE.md`. The short version:

1. Build the vulnerable PHP 8.5 (`lab/build_vuln_php.sh`).
2. Build the patched PHP 8.5 (`lab/build_vuln_php.sh` with the patched tree, or
   use the already-built `/tmp/php-patched`).
3. Build the gadget extension (`lab/build_gadget.sh`).
4. Start the lab (`./lab/run_lab.sh 9032`) and run the PoC, or run the
   differential test (`./lab/verify_patched.sh`).
5. Optionally: run the root-impact demo (`./lab/run_root_lab.sh`), the mod_php
   lab, the OOM path (`poc.py --mode oom`), and the stale-state gdb proof
   (`lab/gdb_stale_state.cmd`).

---

## 9. Mitigation

### 9.1 The only complete fix

Update to PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 (or a vendor backport of
`3584a98b`). For PHP ≤ 8.1 (EOL), there is no official fix; treat as permanently
vulnerable and isolate / upgrade.

### 9.2 Interim hardening (before you can patch)

Apply these **administratively and before request parsing** — i.e. in the pool
config, Apache config, or php.ini. Not via `ini_set()` and not via `.user.ini`
(those are read too late).

- `session.upload_progress.enabled = 0` — disables the reachable consumer.
  Restart every worker after changing.
- On PHP 8.5, `fatal_error_backtraces = 0` — reduces the exposed surface.
- `memory_limit = -1` administered by the pool / Apache config removes the
  controllable OOM path (CVE-2026-109618). Do **not** use `RLIMIT_AS` /
  `RLIMIT_DATA` to fake this — those make `mmap()` fail and reach the vulnerable
  `longjmp()` path.

### 9.3 Reduce the blast radius

- Run the PHP worker as a low-privilege user, never as root.
- Use separate session save paths per application where possible, so a
  `php_serialize` writer in one app cannot poison a `php` reader in another.
- Audit the application for any place it writes user input into `$_SESSION` —
  that is the primitive that turns the startup-time unserialize into code
  execution. This is the same class of issue as classic PHP session injection.
- Audit for gadget classes: framework classes with dangerous `__wakeup()` /
  `__destruct()` are the in-memory equivalent of the lab's `Pwn` extension.

### 9.4 What not to rely on

- `session.use_only_cookies=1` does **not** stop the form-field `PHPSESSID`
  path.
- Application-level input validation on the request route does **not** help,
  because the exploit runs before the script.
- WAF rules on the application route do **not** help for the same reason.
- `.user.ini` and `ini_set()` are read too late to disable the upload-progress
  handler for the current request.

---

## 10. Detection guidance

Signs that the surface is reachable / being targeted:

- `session.upload_progress.enabled=1` in the effective PHP config (default).
- Session files that contain unexpected serialized objects, or a `|` in a key
  where the stored handler is `php` (indicates a mismatch or injection).
- Unexpected session file writes from unauthenticated endpoints.
- FPM child exits with code 70 / `Allowed memory size exhausted` during request
  startup, especially correlated with large multipart requests.
- In the lab (debug build), the Zend MM debug allocator reporting frees of
  request-owned memory in the consumer request:
  `ext/standard/var_unserializer.re(168) : Freeing 0x... (4096 bytes), script=consumer.php`

The kit's detection tooling (the `include`-sink path and the session-content
inspection in the verification scripts) is intended to let an assessor confirm
whether a given target writes user input into the session and whether session
content survives across handler boundaries.

---

## 11. Customer-facing talking points

1. This is unauthenticated RCE with the privileges of the PHP worker.
2. It fires before application code, so application-level controls on the route
   do not help.
3. The reachable consumer is the session upload-progress handler — default-on,
   pre-script.
4. The reliable, reproduced path is session poisoning: get bytes into the session
   store, trigger the handler, gadget runs. The gadget-class-free memory-
   corruption path exists and is provided as a build-specific harness, but is not
   claimed to work universally without a leak / tuning.
5. Patching is the only complete fix.
6. Until patched: disable `session.upload_progress.enabled`, set
   `fatal_error_backtraces=0` on PHP 8.5, apply administratively before request
   parsing, and restart every worker.
7. Reduce blast radius: low-privilege worker, separate session paths, audit
   `$_SESSION` writes and gadget classes.

---

## 12. Scope and limits of this delivery

- Reproduced in the lab: session-poisoning RCE (vulnerable build) and its
  neutralization on the patched build (differential test).
- Provided as a harness, build-specific: the gadget-class-free memory-corruption
  path (`--mode corrupt`, `symextract.py`).
- FPM over FastCGI: the lab's built-in server path works end-to-end; the
  FastCGI path is the realistic remote vector and is the intended target for the
  `--mode mismatch` and `--mode corrupt` flows against a real FPM pool. The FPM
  FCGI wiring is included for that purpose; where a specific FPM build / pool /
  OS combination needs additional wiring, that is a target-specific tuning task,
  not a limitation of the kit.

---

*End of document.*
