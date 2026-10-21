# Lab

| File | Purpose |
|---|---|
| `build_vuln_php.sh` | Clone php-src at the pre-fix PHP-8.5 commit and build it (`--enable-debug`) into `/tmp/php-vuln85`. |
| `build_gadget.sh` | Build the `pwn.so` gadget extension (a class whose `__wakeup()` runs a command) against that PHP. |
| `run_lab.sh [port]` | Start the vulnerable PHP 8.5 with the gadget loaded and run the PoC end to end. |
| `verify_patched.sh` | Differential test: the same PoC against the vulnerable build **and** the patched build (`/tmp/php-patched`). |
| `lab.ini` | Lab php.ini: `session.upload_progress.enabled=1`, `session.use_strict_mode=0`, `memory_limit=8M`, `fatal_error_backtraces=1`. |
| `gadget/` | Source of the gadget extension. |
| `index.php` / `consumer.php` / `producer.php` | Victim scripts. `consumer.php` is the endpoint hit by the exploit request; the RCE happens before it runs. |

Quick start:

```bash
./build_vuln_php.sh
./build_gadget.sh
./run_lab.sh 9032
./verify_patched.sh
```

Notes:
* PHP >= 8.5 exports a `ZEND_VM_KIND` constant that breaks `zend_vm_gen.php`;
  the build script regenerates the VM sources with the containerised PHP 8.3.
* `re2c` is required to configure PHP (`pkexec pacman -S re2c`).

## Root-impact demo

```bash
./run_root_lab.sh          # needs pkexec (password prompt) - runs the worker as root
```

The script starts the vulnerable PHP as root, triggers the PoC and shows the
resulting `/root/poc_rce_proof.txt` plus a redacted listing of the copied
`/etc/shadow`. Set `SHOW_FULL=1` to print the shadow file verbatim.

Cleanup:

```bash
pkexec rm -f /root/poc_rce_proof.txt /root/poc_rce_shadow.txt
```
