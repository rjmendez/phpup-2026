# PHP Bailout State Corruption - CVE-2026-109618 / CVE-2026-109619

**CVSS v4.0 9.2 · unauth · default config · PHP 8.x pre-2026-10-21**

> **2026-10-21 rewrite.** Everything below is grounded in the actual PHP
> security fix - commit `82f8f31b16a` ("Avoid state corruption via
> bailout"), branch `PHP-8.0-CVE-2026-109618-109619` in `php/php-src` -
> not in the leaked PoC artifact's own claims. An earlier version of this
> document described a single-request, multipart-stall heap-spray
> mechanism (149 `t[]` fields, a forged `zend_fcall_info` at fixed byte
> offsets, `FILLUNIT`/delta tables). **That mechanism is deleted, not
> caveated.** It doesn't match the real fix; a real lab reproduction of
> its documented precondition produced a clean `200 OK`, not a crash; and
> VulnCheck independently reports that none of the public PoCs they
> reviewed have the correct mechanism. If you have the old revision of
> this file cached anywhere, discard it.

---

## Root cause: a `longjmp` that skips cleanup

PHP's internal allocator (`zend_mm_safe_error`, `Zend/zend_alloc.c`)
handled an out-of-memory or integer-overflow condition like this, before
the fix:

```c
heap->overflow = 1;
zend_try {
    zend_error_noreturn(E_ERROR, format, ...);   // itself can longjmp
} zend_catch {
} zend_end_try();
heap->overflow = 0;
zend_bailout();        // unconditional longjmp, always taken
exit(1);               // never reached
```

`zend_bailout()` is PHP's internal `setjmp`/`longjmp`-based error-recovery
mechanism - it unwinds the C call stack back to a recovery point,
*skipping whatever cleanup code was between the jump point and the
allocation failure*. If that skipped cleanup was supposed to finish
initializing or tearing down a data structure, the structure is left
half-done while the worker process survives and goes on to handle
further requests.

The fix replaces this entirely:

```c
ZEND_API ZEND_COLD ZEND_NORETURN void zend_mm_safe_error_ex(const char *format, ...)
{
    /* ...build message... */
    fprintf(stderr, "\nFatal error: %s in %s on line %d\n", ...);
    _exit(1);          // hard process exit - no longjmp, no userland error path
}
```

This is **CVE-2026-109618** (GHSA-w8hw-w9fx-j79w, "RCE via OOM
corruption"): an allocator-level OOM/overflow triggers a `longjmp`
mid-operation. The advisory's own wording - *"the patch removes
`longjmp()` for OOM"* - matches this diff exactly.

## The cross-request half: CVE-2026-109619

(GHSA-6wmf-4rv5-p3rp, "RCE via stale global state".) A `longjmp` out of
one request can also skip the normal reset of several globals that live
for the **life of the worker process**, not just one request. The fix
adds explicit resets for each, several with comments stating outright
that the field can be read by a **later, different request on the same
worker**, before that request's own initialization has run:

| Global | Normal reset point | Confirmed risk if skipped |
|---|---|---|
| `EG(user_error_handler)`, `EG(user_exception_handler)`, `EG(user_error_handlers)`, `EG(user_exception_handlers)` | `shutdown_executor()` | read by `zend_error_zstr_at`, "before init_executor" (code comment) |
| `EG(exception)`, `EG(error_handling)` | `shutdown_executor()` | same - same comment |
| `EG(objects_store)` (`object_buckets`, `top`) | `shutdown_executor()` | dangling pointer into the freed previous request's object store |
| `PG(http_globals)[]` (`$_GET`/`$_POST`/`$_COOKIE`/etc. zvals) | `php_request_shutdown()` | "May be accessed before php_request_startup()" (code comment) |
| `PG(modules_activated)` | `php_request_shutdown()` | same |
| `SG(request_info).auth_user`/`auth_password`/`auth_digest`/`content_type_dup`/`current_user` | `sapi_deactivate_module()` | freed but never nulled before the fix - a textbook dangling pointer |

**Confirmed early-reading consumers** - code that runs on the new request
before `init_executor()`/`php_request_startup()` resets the above:
- PHP's own error-reporting path (`zend_error_zstr_at`), reachable via
  certain INI diagnostics applied very early (e.g. `.htaccess`/
  `php_value` under mod_php).
- **`php_session_rfc1867_callback`** - the `session.upload_progress`
  multipart hook (`ext/session/session.c`). Confirmed by this fix's own
  EOL-branch handling: PHP 8.0 doesn't get the full fix backported, only
  a one-line "minimal mitigation" -
  `if (!PS(rfc1867_enabled) || true) { return retval; }` - the `|| true`
  permanently disables the function. That's the PHP security team saying
  "we can't fix this old branch properly, so turn the consumer off,"
  which is as direct a confirmation as this file gets.

## Producer: how an attacker reaches the `longjmp`

CVE-2026-109618's advisory names the practical OOM trigger, and the fix
diff confirms it was real and has been closed:

- Multipart requests without a usable declared `Content-Length` bypass
  the initial `post_max_size` check.
- **A single multipart part could carry an unlimited number of headers**
  before the fix - `main/rfc1867.c`'s `multipart_buffer_headers()`
  previously saved every header line unconditionally. The fix restricts
  it to two header types (`Content-Disposition`, `Content-Type`) and
  skips duplicates via a new `php_mime_get_hdr_value()` lookup. Each
  saved header costs far more memory inside PHP than its size on the
  wire - this, not a 149-field array, is the real amplification vector.
- Empty file fields don't count toward `max_file_uploads` but still
  create file-metadata arrays; nested field names multiply that cost
  further.

**Reproduced, measured (2026-10-21), own lab.** A pre-patch PHP 8.3.6
build (Ubuntu package `8.3.6-0ubuntu0.24.04.12` - note the *installed
default* `8.3.6-0ubuntu0.24.04.13` already had this fix backported
despite the unchanged upstream version string; confirmed via the
`zend_new_array_singleton` symbol's presence/absence in
`/usr/sbin/php-fpm8.3`, had to explicitly downgrade), `pm=static`,
`pm.max_children=1`. One multipart POST, one part, 1,400,000 duplicate
5-byte header lines (`A:0\r\n`), 7,000,111 bytes wire size:

| | `memory_get_peak_usage(true)` |
|---|---|
| Baseline (benign upload, fresh worker) | 2 MB |
| Same payload, **patched** build (`.13`) | 2 MB - identical to baseline |
| Same payload, **pre-patch** build (`.12`) | **408 MB** |

**~58x the 7MB wire payload, ~204x the 2MB baseline** - measured via
PHP's own internal accounting (the exact metric `memory_limit`
enforcement checks against), not an external RSS proxy (an initial RSS-
sampling attempt was flat/misleading: zend_mm arena growth doesn't
necessarily move process RSS the way live-data growth does). Sweeping
`memory_limit` from 2M-256M against the pre-patch build consistently
produced a **hard worker crash and respawn** (`502 Bad Gateway`,
php-fpm log: `child <pid> exited with code 70` then a new child PID
immediately) - not a silent survive-with-corruption. 512M+: clean
`200 OK`, same worker PID before/after. See `examples/pcaps/`
`phpup2026-real-oom-amplification.pcap` and the paired log files for
the full capture (crash / survives / benign-control, three requests).

This confirms CVE-2026-109618's amplification vector and resulting
DoS convincingly. It does **not** by itself demonstrate CVE-2026-109619's
cross-request consumer mechanism, which needs the producer's worker to
*survive* with dangling globals - this trigger, at this scale, kills
the worker outright instead. See "What we have NOT reproduced" below.

## The heap-spray/reclaim step - real, differently triggered

Separate from *how* the bug is triggered, the fix also hardens *how the
freed memory gets reclaimed*: `main/php_variables.c` now initializes
`$_POST`/`$_GET`/`$_COOKIE` with a new `array_init_singleton()`
(`Zend/zend_hash.c`'s `zend_new_array_singleton()`, forcing
`nTableSize = 1`) instead of the default, dynamically-sized
`array_init()`. Forcing these superglobal containers to the smallest
possible table size is a direct defense against an attacker shaping
request data to control what lands in a freed slot.

So: **the heap-spray/reclaim *technique* in the original analysis of this
artifact was real.** What was wrong was the *trigger* - it is not a
same-request stall creating a same-request UAF. It's a `longjmp` on one
(producer) request leaving worker-global state dangling, consumed by a
**later, different request** (consumer) on the **same worker**, before
that request's own initialization has run.

## What we have NOT reproduced - and why php-fpm may be the wrong SAPI to try it on

Built PHP 8.5.0 (genuinely pre-patch - both the `ondrej/php` PPA and
`packages.sury.org` only distribute the already-patched 8.5.12) from
source to test the advisory's "strongest demonstrated case":
`fatal_error_backtraces` enabled.

- **An ordinary uncaught fatal (undefined function call), and an
  ordinary `memory_limit` soft-check fatal (the normal "Allowed memory
  size of N bytes exhausted" warning-then-fatal from a userland
  allocation), both survive cleanly on 8.5** - same worker PID before
  and after, no visible corruption in a follow-up request. Expected:
  these go through PHP's normal, intact exception-to-fatal-error
  pipeline, not the vulnerable low-level allocator path.
- **The same header-explosion payload that produced the 408MB/58x
  amplification above also reproduces on 8.5** (measured 440MB peak
  at `memory_limit=512M`, consistent with 8.3) - but at every
  `memory_limit` below that peak (tested 2M/16M/128M/256M), the
  **worker process dies and is replaced, on 8.5 exactly as on 8.3**.
  `fatal_error_backtraces` being on did not change this.
- **The exit code is always `70`, PHP-FPM's own internal
  "unrecoverable state" exit code** - this is FPM's process-supervision
  model itself recycling the child, not a bare SIGSEGV/kernel-level
  kill. That strongly suggests **php-fpm's own worker-recycling-on-fatal
  behavior is an incidental, pre-existing mitigation** against this
  specific bug's cross-request consumer step: a replaced worker can't
  carry forward dangling globals to the next request. This would also
  explain why the advisory names **mod_php** (embedded in each Apache
  child/thread, no equivalent per-request process recycling) as where
  RCE was confirmed, rather than php-fpm.
- **2026-10-21, built the Apache + mod_php lab and tested the
  hypothesis directly.** Genuinely pre-patch build confirmed the same
  way as the php-fpm builds: `libapache2-mod-php8.3=8.3.6-0maysync1`,
  `zend_new_array_singleton` absent from
  `/usr/lib/apache2/modules/libphp8.3.so`. First pass used a
  deliberately minimal prefork pool (`MaxRequestWorkers 1`) to make
  "which process handled this request" trivial to track by PID - this
  was a methodology mistake: that config makes Apache's own
  spare-server housekeeping churn the single permitted worker on
  *every* request, benign or not (confirmed: PIDs differed after
  purely benign follow-up requests too, with no error logged at all),
  so an apparent "respawn" there is not evidence of anything. Corrected
  by reverting to Apache's stock prefork pool (`StartServers 5`,
  `MinSpareServers 5`, `MaxSpareServers 10`, `MaxRequestWorkers 150`)
  and reading `getmypid()` out of each response body instead of
  diffing `ps` snapshots, so the specific worker that hit the OOM
  condition can be identified and followed regardless of which of the
  pool's idle workers round-robins to serve any given connection.
- **Result: the same header-explosion payload, at `memory_limit=256M`
  (the exact value that produces php-fpm's "exited with code 70,
  child <new-pid> started" crash+respawn on both 8.3 and 8.5), does
  NOT kill the Apache worker.** Confirmed worker PID 1981633 both
  produced the `PHP Fatal error: Allowed memory size of 268435456
  bytes exhausted` log line for the crash request *and* went on to
  successfully answer a later benign request in the same pool's
  round-robin rotation - the complete set of worker PIDs (5, matching
  pool size) was identical before and after the crash request, with no
  new PID ever appearing and none disappearing. This directly confirms
  the original hypothesis: **Apache's mod_php does not recycle a
  worker on this condition the way php-fpm's process supervisor does**,
  so the cross-request window CVE-2026-109619 needs is structurally
  open here in a way it is not on php-fpm.
- **Important caveat, not yet resolved**: the PHP-level error text in
  this mod_php test was the *ordinary*, long-recoverable "Allowed
  memory size of N bytes exhausted (tried to allocate 4096 bytes)"
  message - the routine incremental `memory_limit` check, not the
  distinct "Out of memory (allocated N) (tried to allocate N bytes)"
  message that identifies the actual `zend_mm_safe_error`/bailout
  branch this CVE pair is about. This was true at every tested
  `memory_limit` from 2M to 1024M under mod_php, with no exception.
  The paired php-fpm log (`examples/logs/
  phpup2026-real-oom-amplification-phpfpm.log`) only records FPM's own
  process-supervisor message ("exited with code 70"), not PHP's
  internal error text, so there is no direct side-by-side confirmation
  that the php-fpm crash and this mod_php survival are hitting the
  identical internal code path rather than merely the same outward
  `memory_limit` value. It remains possible mod_php's worker "survives"
  here because this specific test never reaches the actual vulnerable
  bailout branch at all under mod_php's allocation pattern, rather than
  because it reaches that branch and recovers from it. Confirming or
  ruling this out needs either an ASAN/debug PHP build (to catch the
  bailout at the source level directly) or a producer trigger that is
  independently known to force the large/chunk allocation path
  `zend_mm_safe_error` specifically handles.
- Also still unconfirmed: an end-to-end RCE or ASAN use-after-free under
  whichever producer trigger does leave a surviving worker, and which
  early-init paths beyond `php_session_rfc1867_callback` and
  `zend_error_zstr_at` are reachable in a default configuration.

See `examples/pcaps/phpup2026-real-fpm-worker-recycle-85.pcap` and the
paired `php-fpm.log` (both PHP versions' "exited with code 70, child
<new-pid> started" pattern, logged back to back across a `memory_limit`
sweep). The Apache/mod_php worker-survival test above has no matching
pcap artifact yet (it was run to resolve the survive-vs-crash question,
not to produce a shippable detection example) - tracked as open
follow-up work if one is wanted, not claimed as done.

## Patch

Fixed in PHP 8.5.12, 8.4.27, 8.3.36, 8.2.35 (2026-10-21) via the
"avoid state corruption via bailout" hardening above. Source-only
backports exist for 7.4/8.0/8.1; the 8.0 backport disables the
`session.upload_progress` consumer path outright rather than backport
the full fix. **No complete generic configuration mitigation exists**
per the PHP advisory. `session.upload_progress.enabled = 0` closes one
confirmed consumer path; `fatal_error_backtraces = 0` (PHP 8.5 only)
closes the strongest confirmed producer path; neither closes all
variants. See `HARDENING.md`.

A mitigation this file didn't have before, newly derivable from the
cross-request mechanism itself: **preventing worker reuse** (`php-fpm`
`pm.max_requests = 1`, or the mod_php/Apache equivalent
`MaxConnectionsPerChild 1`) makes the consumer step structurally
impossible - no later request can ever land on a worker a prior request
left corrupted, because that worker never serves a second request. This
has an obvious performance cost and is not a substitute for patching.

## References

- Fix commit: `php/php-src` `82f8f31b16a` ("Avoid state corruption via
  bailout"), branch `PHP-8.0-CVE-2026-109618-109619`.
- https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp (CVE-2026-109619)
- https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w (CVE-2026-109618)
- VulnCheck: https://www.vulncheck.com/blog/php2shell-vulnerabilities - *"none of the public PoCs we reviewed have the correct mechanism"*
- `ikow/php2shell-poc`'s "Chain E" hypothesis (session OOM in
  `php_var_unserialize` leaving `BG(unserialize).level` dirty, consumed
  by a later `upload_progress` request, logging `"Session object
  destruction failed"`) is structurally plausible - `BG(unserialize)`'s
  reentrancy-guard pattern and that exact log string are both real,
  confirmed in `ext/standard/var_unserializer.re` and
  `ext/session/session.c:183,2308` - but is a *different* specific chain
  from the one the official fix commit's diff footprint maps onto most
  directly, and has not been independently reproduced by this repo.

*Artifact analyzed: `http://jackalsyn.com/posts/phpupAssets/php-up-2026.tar.gz`, SHA256 `0c254d547cac650bfbcb2275e30c2083737520a51a0511646f1fbb7ed60a0d63`. Given VulnCheck's finding, this artifact's own documented mechanism should not be assumed to be a working exploit for the real CVE - see `iocs.json`'s `this_artifact_only` section, kept only as blocklist-grade IOCs for the artifact itself, not as a description of the real vulnerability.*
