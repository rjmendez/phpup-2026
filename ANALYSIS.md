# PHP session.upload_progress UAF — CVE-2026-109618 / CVE-2026-109619

**CVSS v4.0 9.2 · unauth · default config · PHP 8.x pre-2026-10-21**

---

## Bug

`php_session_rfc1867_callback` (ext/session/session.c) tracks multipart upload
progress by caching two raw `zval*` bucket pointers in
`php_session_rfc1867_progress`:

```c
zval *post_bytes_processed;         /* php_session.h:136 — armed session.c:3316 */
zval *current_file_bytes_processed; /* php_session.h:137 — armed session.c:3342 */
```

Both are captured via `zend_hash_str_find` with no addref and never refreshed
across `php_session_initialize()` calls. Neither is a reference-counted handle;
each is a raw offset into a HashTable's `arData` block.

A timed stall between two multipart chunks — longer than
`session.upload_progress.min_freq` (default 1 s) — forces a second `update()`.
Inside `update()`, `php_session_initialize()` calls `php_session_track_init()`
which calls `zval_ptr_dtor` on the prior decoded session tree, freeing the
`arData` both pointers point into. Subsequent `Z_LVAL_P` writes at session.c:3355
and 3356 land in freed memory.

---

## Two CVEs, two delivery paths

**CVE-2026-109619** — `post_bytes_processed` (session.c:3356)

Armed once at the first `MULTIPART_EVENT_FILE_START`, never refreshed on later
`FILE_START` events. Two-file delivery: file 1 triggers `update#1`; stall >1 s;
file 2 `FILE_DATA` triggers `update#2` (free), then stale `Z_LVAL_P` write.

**CVE-2026-109618** — `current_file_bytes_processed` (session.c:3355)

Re-armed at every `FILE_START`, but `current_file` is immediately moved into
`files[]` via `add_next_index_zval` (`ZVAL_COPY_VALUE`, no addref) — leaving the
array double-owned at refcount 1. When `update()` frees the prior decoded tree,
the aliased `current_file` arData dangles. Single-file delivery: 149 `t[]` spray
first, one file, three chunks (c1 / stall / c2+c3).

---

## Spray and payload

149 multipart `t[]` fields (nTableSize 256, 320-byte `zend_string` bins) reclaim
the freed `arData` slot. Each 288-byte blob is a forged `zend_fcall_info`:

| offset | value | meaning |
|--------|-------|---------|
| +0 | `0x40` (LE qword) | `size` = FCI = 64 |
| +8 | `call_addr` | `function_name` / fn ptr |
| +16 | `0x106` (LE dword) | `IS_STRING_EX` |
| +48 | `0x1` (LE dword) | `param_count` = 1 |
| +64 | `0x1` (byte) | `ZEND_INTERNAL` |
| +152 | `call_addr` | `handler` (HANDLER_OFF = 64+88) |
| +160 | `0x308` (LE dword) | `IS_OBJECT_EX` |
| +200 | `system\0<cmd>\0` | command string (BIN_OFF) |

The stale `Z_LVAL_P` write steers the handler field to `zend_call_function`,
which executes `system(<cmd>)` as the PHP process user.

---

## ASLR

`call_addr = zval_ptr_dtor - delta_call`. Delta is per-build, not portable:

| build | delta |
|-------|-------|
| Ubuntu PHP 8.5.4 profile-21 (author PoC) | `0x43EF0` |
| lsphp82 8.2.34 bookworm | `0xc930` |
| lsphp82 8.2.34 noble | `0xcef0` |
| lsphp82 8.2.34 jammy | `0xd060` |

Wrong delta crashes a worker (DoS). Deltas for all three LiteSpeed 8.2.34
sub-builds are closed from official `-dbg` symbols.

---

## Adjacent write paths

`MULTIPART_EVENT_FILE_END` (session.c:3375) writes through `post_bytes_processed`
again — same stale pointer, same preconditions as CVE-2026-109619.

`MULTIPART_EVENT_END` with `rfc1867_cleanup=0` (default, session.c:3388-3390):
`SEPARATE_ARRAY(&progress->data)` COW-copies when refcount > 1 (after any
`update()`), then `Z_LVAL_P(post_bytes_processed)` writes to the old, still-live
arData. `php_session_initialize()` inside `update(force=1)` then frees it, but the
pointer is never read again. **Logic bug, not an independently exploitable UAF.**

---

## Codebase survey

Source surveyed: ext/session/session.c, php_session.h, main/rfc1867.c,
Zend/zend_hash.c/h, zend_types.h, zend_fibers.c, zend_generators.c (PHP-8.4,
commit b9ea38ef, pre-patch).

The stale-`zval*`-bucket-pointer pattern is **unique to
`php_session_rfc1867_progress`**. Specifically:

- All other `zend_hash_str_find` stores in session.c target local variables
  (`data`, `ppid`, `cancel_upload`) scoped within the calling function.
- `zend_fiber_vm_state::vm_stack_top/end` are VM stack pointers, not HashTable
  bucket pointers — captured from and restored to `EG()` atomically at
  yield/resume.
- `zend_hash_iterator_pos_ex` (zend_hash.c:639) inlines `SEPARATE_ARRAY` but
  immediately re-fetches the iterator pointer (`iter = EG(ht_iterators) + idx`)
  in case `EG(ht_iterators)` was reallocated — the correct pattern.
- Generator `fast_call` (`ZEND_CALL_VAR` into execute_data) is local scope,
  never persisted.

---

## Fix

**Replace `zval*` with `zend_long` in `php_session_rfc1867_progress`.** Write
the scalar values directly; sync back to the HashTable via a fresh
`zend_hash_str_find` call after each `php_session_initialize()` returns.

Re-anchoring inside `update()` (option B) is incomplete: the
`MULTIPART_EVENT_END` stale write at session.c:3390 occurs *before* the
`update()` call, so a re-anchor inside `update()` does not protect it.

---

## History

Bug present since PHP 5.4 (upload_progress introduction). Precursor:
CVE-2020-7062 — NULL dereference in the same `MULTIPART_EVENT_END` /
`cleanup=0` handler, fixed by adding the `Z_ISUNDEF(progress->data)` guard
still present today. The raw pointer caching was not addressed.

Patch ETA: 2026-10-21 14:00 UTC (PHP 8.2.35+, 8.4.5+). EOL branches receive
no fix.

---

## Detection

Generic, mechanics-based — works against any exploit for this bug class, not
just the released tool:

```
required fields:  PHP_SESSION_UPLOAD_PROGRESS + PHPSESSID in a multipart POST
spray geometry:    body far larger than a tracked upload's own form fields need
payload content:   dangerous-function string (system/exec/passthru/shell_exec/
                   popen/proc_open) inside the upload_progress context
structural match:  body bytes @+16: 06 01 00 00 (IS_STRING_EX)
                   @+160: 08 03 00 00 (IS_OBJECT_EX)  — fixed by PHP's zval ABI,
                   not by any tool's code
```

Rules: `rules/suricata.rules`, `rules/yara.yar` (source/binary fingerprint,
intentionally tool-specific), `rules/sigma/`, `rules/sentinel/` in this repo.

The one released PoC's literal strings (boundary `B7kQpoc61*`, User-Agent
`php2shell-*`, default session ID `a1b2c3d4e5f6a7b8c9d0e1f2a3`, canary
`JACKALPOC`) are kept as blocklist-grade IOCs under `this_artifact_only` in
`iocs.json` — trivial for an attacker to change, so not relied on above as
the detection strategy.

---

## Mitigation

```ini
session.upload_progress.enabled = 0
```

Patch to 8.2.35+ / 8.4.5+ when available. PHP 5/6/7 are permanently exposed.

---

*Artifact: `http://jackalsyn.com/posts/phpupAssets/php-up-2026.tar.gz`*  
*SHA256: `0c254d547cac650bfbcb2275e30c2083737520a51a0511646f1fbb7ed60a0d63`*  
*Original research: J4ck3LSyN / Acd421 / Arch&Yuki / Atlas*  
*CVE-2026-109618 independently confirmed: watchTowr*
