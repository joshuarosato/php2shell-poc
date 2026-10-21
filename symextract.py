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

symextract.py — per-build symbol extraction + ASLR base resolution.

Why this exists: `zend_call_function = zval_ptr_dtor - delta_call` and the
delta changes with EVERY build (measured: 8.4.4-cli 0xAFB80, 8.4.4-fpm
0xAFE80, 8.2.34-fpm 0xCF40, lsphp82-8.2.34 bookworm/noble/jammy
0xC930/0xCEF0/0xD060, author's Ubuntu 8.5.4 profile 0x43EF0, jackalsyn's
self-built ASAN 8.4.4-fpm 0x2B273A). A wrong delta faults a worker (DoS),
not RCE — extraction is mandatory, never guess.

Docker-official php images are STRIPPED (.symtab empty), but PHP links with
--export-dynamic so ZEND_API symbols survive in .dynsym. This module parses
ELF64 .dynsym/.dynstr directly in pure stdlib — no nm/readelf/binutils, no
WSL — so it runs natively on Windows against a docker-copied binary.

Usage:
  python symextract.py --binary php-fpm                 # static vaddrs + delta
  python symextract.py --maps-file maps.txt             # + runtime base/addr
  python symextract.py --docker php-fpm-test            # exec + maps in one shot
"""

import argparse
import struct
import subprocess
import sys
import os
import tempfile

SYMS = ("zval_ptr_dtor", "zend_call_function")


# ------------------------------------------------------------- ELF parsing --

def parse_dynsym(binary: str) -> dict[str, int]:
    """Minimal ELF64 little-endian .dynsym reader -> {name: st_value}."""
    with open(binary, "rb") as fh:
        data = fh.read()
    if data[:4] != b"\x7fELF":
        raise ValueError(f"{binary}: not an ELF file")
    if data[4] != 2 or data[5] != 1:
        raise ValueError(f"{binary}: need ELF64 little-endian")

    e_shoff, = struct.unpack_from("<Q", data, 0x28)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
         sh_link, sh_info, sh_addralign, sh_entsize) = \
            struct.unpack_from("<IIQQQQIIQQ", data, off)
        sections.append(dict(name=sh_name, type=sh_type, offset=sh_offset,
                             size=sh_size, link=sh_link, entsize=sh_entsize))

    shstr = sections[e_shstrndx]

    def secname(s):
        start = shstr["offset"] + s["name"]
        end = data.index(b"\x00", start)
        return data[start:end].decode()

    out: dict[str, int] = {}
    for s in sections:
        if s["type"] not in (2, 11):  # SHT_SYMTAB=2, SHT_DYNSYM=11
            continue
        strtab = sections[s["link"]]
        n = s["size"] // 24  # Elf64_Sym = 24 bytes
        for i in range(n):
            off = s["offset"] + i * 24
            st_name, st_info, st_other, st_shndx, st_value, st_size = \
                struct.unpack_from("<IBBHQQ", data, off)
            if st_name == 0:
                continue
            start = strtab["offset"] + st_name
            end = data.index(b"\x00", start)
            name = data[start:end].decode("latin1", "replace")
            if name in SYMS:
                out[name] = st_value
    missing = [s for s in SYMS if s not in out]
    if missing:
        raise ValueError(
            f"symbols not found in .dynsym: {missing} "
            f"(binary may not be a PHP --export-dynamic build)")
    out["delta_call"] = (out["zval_ptr_dtor"] - out["zend_call_function"]) & (2**64 - 1)
    return out


# ------------------------------------------------------------ maps parsing --

def parse_base(maps_text: str, needle: str = "php") -> int:
    """Lowest r--p offset-0 mapping of the needle binary = PIE load bias.
    php-fpm workers fork from the master and INHERIT this base."""
    for line in maps_text.splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        perms, offset, path = parts[1], parts[2], parts[5]
        if perms == "r--p" and offset == "00000000" and needle in path:
            return int(line.split("-")[0], 16)
    raise ValueError(f"no r--p offset-0 mapping of {needle!r} in maps")


def resolve(binary: str = None, maps_text: str = None) -> dict:
    """Static symbols + optional runtime resolution."""
    res = {}
    if binary:
        res.update(parse_dynsym(binary))
    if maps_text:
        base = parse_base(maps_text)
        res["base"] = base
        if "zend_call_function" in res:
            res["runtime_zend_call_function"] = base + res["zend_call_function"]
            res["runtime_zval_ptr_dtor"] = base + res["zval_ptr_dtor"]
    return res


def docker_resolve(container: str,
                   binary_path: str = "/usr/local/sbin/php-fpm") -> dict:
    """One-shot: docker cp the serving binary, read PID1 maps, resolve.
    MSYS_NO_PATHCONV=1 keeps Git-bash from rewriting container paths."""
    env = dict(os.environ, MSYS_NO_PATHCONV="1")
    tmp = tempfile.mktemp(suffix=".elf")
    subprocess.run(["docker", "cp", f"{container}:{binary_path}", tmp],
                   check=True, env=env)
    maps = subprocess.run(["docker", "exec", container, "cat", "/proc/1/maps"],
                          capture_output=True, text=True, env=env).stdout
    res = resolve(tmp, maps)
    os.unlink(tmp)
    return res


# ----------------------------------------------------------------- main --

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", help="path to php/php-fpm binary (docker cp'd)")
    ap.add_argument("--maps-file", help="/proc/<pid>/maps dump (optional)")
    ap.add_argument("--docker", help="container name: cp binary + maps in one shot")
    ap.add_argument("--docker-binary", default="/usr/local/sbin/php-fpm")
    a = ap.parse_args()

    if a.docker:
        res = docker_resolve(a.docker, a.docker_binary)
    elif a.binary:
        maps_text = open(a.maps_file).read() if a.maps_file else None
        res = resolve(a.binary, maps_text)
    else:
        ap.error("need --binary, or --docker")
    for k, v in sorted(res.items()):
        print(f"{k:32} {v:#x}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
