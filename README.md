# phpup-2026

IOCs and detection rules for **CVE-2026-109618** / **CVE-2026-109619**.

Two heap UAF bugs in PHP `ext/session/session.c` (`php_session_rfc1867_progress`).
`post_bytes_processed` and `current_file_bytes_processed` are raw `zval*` bucket
pointers cached at FILE_START. A timed stall (`session.upload_progress.min_freq`,
default 1s) triggers `zend_hash_update` → `zval_ptr_dtor` on the decoded session
tree, dangling both pointers. A 149-element `t[]` spray reclaims the freed arData
with forged `zend_fcall_info` → `zend_call_function` → `system()`.

**CVSS v4.0 9.2 · unauthenticated · default config · PHP 8.x pre-2026-10-21**

Artifact: `http://jackalsyn.com/posts/phpupAssets/php-up-2026.tar.gz`  
SHA256: `0c254d547cac650bfbcb2275e30c2083737520a51a0511646f1fbb7ed60a0d63`

## Files

| Path | Format |
|------|--------|
| `iocs.json` | machine-readable IOCs — generic (structural) and `this_artifact_only` (one PoC's literal strings) kept separate |
| `rules/suricata.rules` | Suricata 7+ — generic, mechanics-based (SID 9109627–9109632) |
| `rules/yara.yar` | YARA 4+ — tool/source fingerprint (intentionally PoC-specific; file/memory forensics use case, not network detection) |
| `rules/sigma/` | Sigma (one rule per file) — generic, mechanics-based |
| `rules/sentinel/phpup2026.kql` | Microsoft Sentinel KQL — generic, mechanics-based |
| `ANALYSIS.md` | technical writeup: UAF chain, codebase survey, fix analysis |

## Detection philosophy

Suricata and Sigma rules key on the vulnerability's actual mechanics — the
required `PHP_SESSION_UPLOAD_PROGRESS`+`PHPSESSID` combination, spray-sized
bodies, dangerous-function markers, and the forged `zend_fcall_info`/zval
byte layout PHP's own struct ABI dictates — not on one released tool's
hardcoded multipart boundary, User-Agent, session ID, or output canary.
Those are trivial to change and will not survive a rewritten exploit. The
one released PoC's literal strings are kept as blocklist-grade IOCs under
`this_artifact_only` in `iocs.json`, not presented as the detection
strategy. YARA remains PoC-source/binary fingerprinting by design — that's
a different use case (identifying the tool on disk) from network detection
of the attack.

## Mitigation

```ini
; disable the vulnerable code path entirely
session.upload_progress.enabled = 0
```

Patch: PHP 8.2.35+ / 8.4.5+. PHP 5/6/7 are EOL and will not receive fixes.

## Credits

Original research: J4ck3LSyN / Acd421 / Arch&Yuki / Atlas  
watchTowr independently confirmed CVE-2026-109618.
