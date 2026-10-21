#!/usr/bin/env bash
# Build the lab "gadget" extension.
#
# It provides a class whose __wakeup() executes a command.  It stands in for
# the gadget classes that real applications expose (framework classes such as
# Symfony/Guzzle/Monolog handlers).  The point of the PoC is *when* __wakeup()
# runs - during request startup, before any application code - not the gadget
# itself.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PHP_PREFIX="${PHP_PREFIX:-/tmp/php-vuln85}"
BUILD="${BUILD:-/tmp/opencode/scratchpad/ext-pwn}"

rm -rf "$BUILD"
mkdir -p "$BUILD"
cp "$HERE/gadget/pwn.c" "$HERE/gadget/config.m4" "$BUILD/"
cd "$BUILD"
"$PHP_PREFIX/bin/phpize"
./configure --with-php-config="$PHP_PREFIX/bin/php-config"
make -j"$(nproc)"
echo "gadget extension: $BUILD/modules/pwn.so"
