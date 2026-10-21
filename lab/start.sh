#!/usr/bin/env bash
set -e
FPM=/home/joshua/.local/share/mise/installs/static-php-fpm/8.5.7/bin/php-fpm
mkdir -p /tmp/poctest
cp ../payloads/* /tmp/poctest/
$FPM -y "$(pwd)/fpm.conf" -c "$(pwd)/php.ini" &
echo "FPM started on 127.0.0.1:9013"
