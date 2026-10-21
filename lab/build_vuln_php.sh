#!/usr/bin/env bash
# Build the *vulnerable* PHP 8.5 (pre-patch) used by the lab.
#
#   upstream fix: php-src commit 3584a98b "Avoid state corruption via bailout"
#                 (GHSA-w8hw-w9fx-j79w / GHSA-6wmf-4rv5-p3rp)
#   vulnerable  : the commit right before the fix on the PHP-8.5 branch
#
# The tree is built with --enable-debug so that the Zend MM debug allocator
# reports the stale-state use-after-free.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-/tmp/opencode/scratchpad}"
SRC="$WORK/php-src"
VULN_COMMIT="${VULN_COMMIT:-73e2bad9}"   # PHP-8.5, parent of the fix
PREFIX="${PREFIX:-/tmp/php-vuln85}"

mkdir -p "$WORK"
if [ ! -d "$SRC/.git" ]; then
  git clone --filter=blob:none https://github.com/php/php-src.git "$SRC"
fi
cd "$SRC"
git fetch --depth 20 origin PHP-8.5:PHP-8.5 || true
git checkout -B vuln-85 "$VULN_COMMIT"
./buildconf --force
./configure --enable-debug --enable-fpm --with-mysqli --prefix="$PREFIX"

# PHP >= 8.5 exposes a ZEND_VM_KIND constant, which breaks zend_vm_gen.php.
# Generate the VM sources with an older PHP (containerised) instead.
if command -v podman >/dev/null; then
  podman run --rm -v "$SRC":/src -w /src/Zend docker.io/library/php:8.3-cli \
    php zend_vm_gen.php --with-vm-kind=HYBRID
else
  php zend_vm_gen.php --with-vm-kind=HYBRID
fi

make -j"$(nproc)"
make install
echo "vulnerable PHP installed in $PREFIX"
