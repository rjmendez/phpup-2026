# phpup-2026

IOCs and detection rules for **CVE-2026-109618** and **CVE-2026-109619** -
a single PHP security fix (`php/php-src` commit `82f8f31b16a`, "Avoid
state corruption via bailout") closing a `longjmp`-based state-corruption
class of bug with two confirmed exploitation chains.

> **2026-10-21 rewrite.** This repo previously described a single-request,
> multipart-stall heap-spray mechanism for CVE-2026-109619 only, derived
> from the leaked PoC artifact's own claims (149 `t[]` fields, a forged
> `zend_fcall_info` at fixed byte offsets). **That mechanism is deleted,
> not caveated** - it doesn't match the real fix, a real lab reproduction
> of its precondition produced a clean `200 OK`, and VulnCheck
> independently reports that none of the public PoCs they reviewed have
> the correct mechanism. See `ANALYSIS.md` for the full rewrite, grounded
> in the actual fix commit rather than the artifact.

PHP's internal allocator handled an OOM/overflow condition with a
`longjmp`-based "bailout" that could skip cleanup code mid-operation,
leaving several worker-persistent globals (error handlers, exception
state, object store, `$_GET`/`$_POST`/`$_COOKIE` zvals, SAPI auth fields)
dangling. A later, *different* request landing on the *same worker
process* can read that stale state - `session.upload_progress`'s
multipart hook is one confirmed early-reading consumer - before that
request's own initialization resets it. Practical producer trigger:
`main/rfc1867.c` previously let a single multipart part carry an
unlimited number of headers, cheaply driving the allocator into the
vulnerable OOM path.

**CVSS v4.0 9.2 · unauthenticated · default config · PHP 8.x pre-2026-10-21**

Artifact analyzed (treat its own technical claims as unverified - see
`iocs.json`): `http://jackalsyn.com/posts/phpupAssets/php-up-2026.tar.gz`
SHA256 `0c254d547cac650bfbcb2275e30c2083737520a51a0511646f1fbb7ed60a0d63`

## Official status (2026-10-21)

PHP shipped fixes for both CVEs together, in one commit:

| Branch | Fixed in |
|--------|----------|
| 8.5 | 8.5.12 |
| 8.4 | 8.4.27 |
| 8.3 | 8.3.36 |
| 8.2 | 8.2.35 |

PHP 8.1 and older receive no fix from the PHP project (source-only
backports exist for 7.4/8.0/8.1; the 8.0 backport disables the
`session.upload_progress` consumer path outright rather than backport
the full fix - some distros/LTS vendors backport further, check with
your vendor).

- Fix commit: `php/php-src` `82f8f31b16a`, branch `PHP-8.0-CVE-2026-109618-109619`
- [Official advisory](https://www.php.net/archive/2026.php#2026-10-21-5)
- [CVE-2026-109618 - GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) ("RCE via OOM corruption" - the `longjmp` removal)
- [CVE-2026-109619 - GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) ("RCE via stale global state" - the cross-request consumer half)

**Both CVEs are in scope here now.** They are fixed by the same commit and
share the same root-cause class; the advisories distinguish them by
confirmed trigger/consumer path, not by separate code. `ANALYSIS.md`,
`iocs.json`, and `rules/` cover both.

## Files

| Path | Format |
|------|--------|
| `iocs.json` | machine-readable IOCs - real mechanism details (fix-commit-grounded) and `this_artifact_only` (one PoC's literal strings) kept separate |
| `rules/suricata.rules` | Suricata 7+ - OOM-amplification + feature-presence signals (SID 9109627, 9109633 active, both live-fire verified including against a real legitimate multi-file upload; 9109628-9109632, 9109634, 9109635, 9109636 retired - see the file's own retired-rules section) |
| `rules/yara.yar` | YARA 4+ - tool/source fingerprint (intentionally PoC-specific; file/memory forensics use case, not network detection) |
| `rules/sigma/` | Sigma (one rule per file) |
| `rules/sentinel/phpup2026.kql` | Microsoft Sentinel KQL - feature-presence + process-spawn only; the OOM-amplification queries this file once had were retired 2026-10-21 (built on an AzureDiagnostics field, `requestBody_s`, that does not exist - see the file's own header comment) |
| `rules/sentinel/analytics-rules/` | Sentinel Analytics Rule YAML (one rule per file) - same retirement applies, only the process-spawn rule remains |
| `ANALYSIS.md` | technical writeup: the real fix-commit mechanism, codebase survey, what's unreproduced |
| `HARDENING.md` | defense-in-depth hardening guide, layered beyond the primary mitigation |
| `examples/` | sanitized pcap/http/log samples - see `examples/INDEX.md` (all samples from before the mechanism rewrite that depended on the now-retired trigger theory were deleted, not kept; everything currently in this directory is a real capture validated against the current rules - see INDEX.md's per-file verification record) |
| `scripts/sigma_eval.py` | minimal real Sigma-condition evaluator |

## Detection philosophy

Rules key on the real, fix-confirmed mechanics: the `rfc1867`
duplicate/excessive-header OOM-amplification producer signal (CVE-2026-109618,
doesn't require `session.upload_progress` at all), the
`PHP_SESSION_UPLOAD_PROGRESS`+`PHPSESSID` feature-presence precondition for
the confirmed consumer path (CVE-2026-109619), and a generic
PHP-worker-spawns-shell post-exploitation indicator. **Not** on the
forged-`zend_fcall_info` byte layout or spray-count theory from the prior
revision - those came from the leaked PoC artifact's own code, which
VulnCheck reports does not have the correct mechanism, and are retired,
not kept as low-confidence signals. PoC literal strings are in
`this_artifact_only` in `iocs.json`. YARA is PoC/source fingerprinting
(disk forensics, not network detection).

**Known, not solved:** the cross-request "same worker" requirement is not
visible from any standard web/WAF/MDE log source in this rule set - none
of them carry a worker/process identifier tied to a request. Rules here
detect the producer-side amplification technique and generic
post-exploitation symptoms; they do not and cannot confirm the UAF itself
occurred. See `ANALYSIS.md`'s "What we have NOT reproduced."

## Mitigation

```ini
; closes one confirmed consumer path (CVE-2026-109619)
session.upload_progress.enabled = 0
; closes the strongest confirmed producer path (CVE-2026-109619, PHP 8.5 only)
fatal_error_backtraces = 0
```

**No complete generic configuration mitigation exists** per the PHP
advisory - these close specific confirmed paths, not the whole bug class.
Patch: PHP 8.5.12, 8.4.27, 8.3.36, or 8.2.35 (all released 2026-10-21).
PHP 5/6/7 are EOL and will not receive fixes; PHP 8.1 and older get no
fix from the PHP project.

A mitigation newly derivable from the cross-request mechanism itself:
**prevent worker reuse** (`php-fpm` `pm.max_requests = 1`, or the
mod_php/Apache equivalent `MaxConnectionsPerChild 1`) - this makes the
consumer step structurally impossible, since no later request can ever
land on a worker a prior request left corrupted. Performance cost;
not a substitute for patching. See `HARDENING.md`.

## Credits

Original research: J4ck3LSyN / Acd421 / Arch&Yuki / Atlas
watchTowr independently confirmed CVE-2026-109618.
VulnCheck: independent review noting public PoCs (including, plausibly,
the one analyzed here) do not have the correct mechanism - the finding
that prompted this rewrite.
