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

## What we have NOT reproduced

- An end-to-end RCE, or even a confirmed crash/ASAN use-after-free,
  under the real trigger (header-explosion OOM on a producer request,
  followed by an `upload_progress` or early-error-path consumer request
  on the same worker).
- Which early-init paths beyond `php_session_rfc1867_callback` and
  `zend_error_zstr_at` are reachable in a default configuration.

Needs a debug/ASAN PHP build and a pinned (`pm=static`, small pool)
php-fpm/mod_php lab, forcing worker reuse so a producer and consumer
request are guaranteed to land on the same process. Tracked as open
follow-up work, not claimed as done.

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
