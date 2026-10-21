"""Copyright 2026 Joshua Rosato.

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

Minimal FastCGI client for talking to PHP-FPM."""
import socket, struct


def _make_record(rec_type, req_id, content):
    pad = (8 - (len(content) % 8)) % 8
    header = struct.pack(">BBHHBB", 1, rec_type, req_id, len(content), pad, 0)
    return header + content + b"\x00" * pad


def _enc_len(n):
    if n < 128:
        return bytes([n])
    return struct.pack(">I", n | 0x80000000)


def fcgi_request(host, port, params, stdin=b"", timeout=30):
    conn = socket.create_connection((host, port), timeout=timeout)
    req_id = 1
    conn.sendall(_make_record(1, req_id, struct.pack(">H B 5x", 1, 0)))
    data = b""
    for k, v in params.items():
        kb, vb = k.encode(), v.encode()
        data += _enc_len(len(kb)) + _enc_len(len(vb)) + kb + vb
    off = 0
    while off < len(data):
        chunk = data[off:off + 65535]
        conn.sendall(_make_record(4, req_id, chunk))
        off += 65535
    conn.sendall(_make_record(4, req_id, b""))
    off = 0
    while off < len(stdin):
        chunk = stdin[off:off + 65535]
        conn.sendall(_make_record(5, req_id, chunk))
        off += 65535
    conn.sendall(_make_record(5, req_id, b""))
    conn.settimeout(timeout)
    out = b""
    try:
        while True:
            d = conn.recv(65536)
            if not d:
                break
            out += d
    except socket.timeout:
        pass
    conn.close()
    return out


def parse_body(raw):
    body = b""
    i = 0
    n = len(raw)
    while i + 8 <= n:
        version, rtype, rid, clen, pad, reserved = struct.unpack_from(">BBHHBB", raw, i)
        if version != 1:
            break
        i += 8
        if i + clen + pad > n:
            break
        if rtype == 6:
            body += raw[i:i + clen]
        i += clen + pad
    return body