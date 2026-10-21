# phpup-2026

IOCs and detection rules for **CVE-2026-109619** (PHP `session.upload_progress`
heap UAF). This repo originally treated CVE-2026-109618 as the same bug under
a second delivery path; PHP's official 2026-10-21 advisory corrects that —
109618 is a separate, unrelated **OOM-corruption** bug. See "Official status"
below.

One heap UAF in PHP `ext/session/session.c` (`php_session_rfc1867_progress`).
`post_bytes_processed` and `current_file_bytes_processed` are raw `zval*` bucket
pointers cached at FILE_START. A timed stall (`session.upload_progress.min_freq`,
default 1s) triggers `zend_hash_update` → `zval_ptr_dtor` on the decoded session
tree, dangling both pointers. A 149-element `t[]` spray reclaims the freed arData
with forged `zend_fcall_info` → `zend_call_function` → `system()`.

**CVSS v4.0 9.2 · unauthenticated · default config · PHP 8.x pre-2026-10-21**

Artifact: `http://jackalsyn.com/posts/phpupAssets/php-up-2026.tar.gz`  
SHA256: `0c254d547cac650bfbcb2275e30c2083737520a51a0511646f1fbb7ed60a0d63`

## Official status (2026-10-21)

PHP shipped fixes for both CVE-2026-109618 and CVE-2026-109619 today:

| Branch | Fixed in |
|--------|----------|
| 8.5 | 8.5.12 |
| 8.4 | 8.4.27 |
| 8.3 | 8.3.36 |
| 8.2 | 8.2.35 |

PHP 8.1 and older receive no fix from the PHP project (some distros/LTS
vendors backport — check with your vendor).

- [Official advisory](https://www.php.net/archive/2026.php#2026-10-21-5)
- [CVE-2026-109618 — GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) ("RCE via OOM corruption" — **not** this repo's bug, see below)
- [CVE-2026-109619 — GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) ("RCE via stale global state" — this repo's bug)

**CVE-2026-109618 is out of scope for this repo.** Per the advisory, its root
cause is out-of-memory handling interrupting PHP while internal request data
is only partially initialized, unrelated to `session.upload_progress`.
`ANALYSIS.md`, `iocs.json`, and every rule under `rules/` here address
CVE-2026-109619 only. `HARDENING.md` documents CVE-2026-109618's own
mitigations (`memory_limit`, `post_max_size`, cgroup limits) as a separate,
uncovered item.

## Files

| Path | Format |
|------|--------|
| `iocs.json` | machine-readable IOCs — generic (structural) and `this_artifact_only` (one PoC's literal strings) kept separate |
| `rules/suricata.rules` | Suricata 7+ — generic, mechanics-based (SID 9109627–9109632) |
| `rules/yara.yar` | YARA 4+ — tool/source fingerprint (intentionally PoC-specific; file/memory forensics use case, not network detection) |
| `rules/sigma/` | Sigma (one rule per file) — generic, mechanics-based |
| `rules/sentinel/phpup2026.kql` | Microsoft Sentinel KQL — generic, mechanics-based |
| `rules/sentinel/analytics-rules/` | Sentinel Analytics Rule YAML (one rule per file) — generic, mechanics-based |
| `ANALYSIS.md` | technical writeup: UAF chain, codebase survey, fix analysis |
| `HARDENING.md` | defense-in-depth hardening guide, layered beyond the primary mitigation |
| `examples/` | sanitized pcap/http/log samples for validating the rules above — see `examples/INDEX.md` |
| `scripts/sigma_eval.py` | minimal real Sigma-condition evaluator, used to catch a `cs-bytes|contains` bug in two sigma rules against real captured events |

## Detection philosophy

Rules key on mechanics — `PHP_SESSION_UPLOAD_PROGRESS`+`PHPSESSID`,
spray-sized bodies, dangerous-function markers, and the forged
`zend_fcall_info`/zval byte layout PHP's ABI dictates — not on any one
tool's hardcoded boundary, User-Agent, session ID, or canary. PoC literal
strings are in `this_artifact_only` in `iocs.json`. YARA is PoC/source
fingerprinting (disk forensics, not network detection). Scope: CVE-2026-109619
only — see "Official status" above for CVE-2026-109618, which this repo does
not cover.

## KQL / Sentinel field mappings

`rules/sentinel/phpup2026.kql` and `rules/sentinel/analytics-rules/` use
Microsoft Sentinel/Log Analytics table column names, which differ
cosmetically from the W3C field names `rules/sigma/` uses for the same
underlying data, and from this repo's own real lab capture in
`examples/`. No live Log Analytics workspace was available to run the
KQL itself — these mappings are checked by hand against the real
captured field values, not against a live `W3CIISLog`/`DeviceProcessEvents`
table.

| KQL column (table) | Sigma field (`rules/sigma/`) | Real value seen in this lab |
|---|---|---|
| `csMethod` (`W3CIISLog`) | `cs-method` | `"POST"` |
| `csHeaders` (`W3CIISLog`) | `cs-headers` | `"multipart/form-data; boundary=..."` |
| `csCookie` (`W3CIISLog`) | `cs-cookie` | `"PHPSESSID=..."` |
| `csBytes` (`W3CIISLog`) | `cs-bytes` | `58403` (oversized) / `4220` (benign) — numeric; see the `cs-bytes|contains` bug `scripts/sigma_eval.py` caught and fixed in the sigma rules |
| `csUriQuery` (`W3CIISLog`) | — (no sigma equivalent) | not populated in this lab — `PHP_SESSION_UPLOAD_PROGRESS` was sent as a multipart body field, not a query string, same as real-world legitimate usage |
| `InitiatingProcessFileName` (`DeviceProcessEvents`) | `ParentCommandLine` (contains-match on full cmdline, not just the filename) | `php-fpm8.3` / `cron` (both real, see `examples/logs/phpup2026-sysmonlinux-*.log`) |
| `InitiatingProcessAccountName`/`AccountDomain`/`AccountSid` (`DeviceProcessEvents`) | `User` | `www-data` (real) |
| `FileName`/`ProcessCommandLine` (`DeviceProcessEvents`) | `CommandLine` | `/bin/sh -c "id; whoami; sleep 1.5"` (real) |

Tables this repo's KQL targets but this lab never produced real data for
— not locally validated at all, logic-reviewed only: `CommonSecurityLog`,
`AzureDiagnostics`, `DeviceNetworkEvents`, `SecurityEvent`.

**Known issue, not yet fixed:** query `[T2-4]` in `phpup2026.kql` (and the
matching `phpup2026-WorkerCrashPattern.yaml` Sentinel Analytics Rule) key
on a `scStatus in ("200", "502", "503")` worker-crash ratio. That crash
signal shares the disproven premise in `ANALYSIS.md`'s 2026-10-21
mechanism finding — this lab's stall test produced a clean `200 OK`, not
a `502`/`503`, under the exact precondition that was supposed to crash
the worker. Treat `WorkerCrashPattern` as unvalidated against real
behavior until it's revised or caveated the same way.

## Mitigation

```ini
; disable the vulnerable code path entirely
session.upload_progress.enabled = 0
```

Patch: PHP 8.5.12, 8.4.27, 8.3.36, or 8.2.35 (all released 2026-10-21, fixes
CVE-2026-109619). PHP 5/6/7 are EOL and will not receive fixes. PHP 8.1 and
older: no fix from the PHP project.

## Credits

Original research: J4ck3LSyN / Acd421 / Arch&Yuki / Atlas  
watchTowr independently confirmed CVE-2026-109618.
