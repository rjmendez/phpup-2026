# Sample index

One row per file added under `pcaps/`, `http/`, or `logs/`. Keep it current —
an unlabeled sample isn't usable for regression-testing the rules.

| File | CVE | Path | Build | Outcome | Should trigger | Notes |
|------|-----|------|-------|---------|-----------------|-------|
| `pcaps/phpup2026-real-blob-CVE-109618-dtor0.pcap` | 109618 | `FILE_DATA stall` | n/a (dtor=0) | crash (null call addr) | `9109629`, `9109630` | 5-packet TCP session (SYN/SYNACK/ACK/DATA/FIN). src=`203.0.113.42` (TEST-NET-3). Real `forge()` blob layout: IS_STRING_EX@+16, IS_OBJECT_EX@+160, `system\0id\0`@+200. `PHP_SESSION_UPLOAD_PROGRESS` + PHPSESSID cookie present. No RCE (call_addr=0). |
| `pcaps/phpup2026-benign-legitimate-upload.pcap` | — | — | — | benign | **none** (false-positive check) | 6-packet session with server response. src=`198.51.100.7` (TEST-NET-2). Legitimate `session.upload_progress` usage: single `PHP_SESSION_UPLOAD_PROGRESS` field + `PHPSESSID` cookie + one small JPEG file (~3.8KB). No spray, no binary zval markers, no dangerous function strings, body < 40KB. Should trigger `9109627` (policy/inventory) and nothing else. |

**Path** — `FILE_DATA stall` (the confirmed exploit path) or `END` (ruled out,
logic bug only — see root `ANALYSIS.md`; a capture of this path is a
good negative/no-alert sample, not a positive).

**Outcome** — `rce`, `crash` (wrong per-build offset), or `benign` (legitimate
upload_progress usage, no spray — false-positive check).

**Should trigger** — which rule IDs from `rules/suricata.rules`,
`rules/sigma/`, or `rules/sentinel/` this sample is expected to fire (or, for
`benign`, expected *not* to fire).
