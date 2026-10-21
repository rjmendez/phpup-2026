# Sample index

One row per file added under `pcaps/`, `http/`, or `logs/`. Keep it current —
an unlabeled sample isn't usable for regression-testing the rules.

| File | CVE | Path | Build | Outcome | Should trigger | Notes |
|------|-----|------|-------|---------|-----------------|-------|
| _(none yet)_ | | | | | | |

**Path** — `FILE_DATA stall` (the confirmed exploit path) or `END` (ruled out,
logic bug only — see root `ANALYSIS.md`; a capture of this path is a
good negative/no-alert sample, not a positive).

**Outcome** — `rce`, `crash` (wrong per-build offset), or `benign` (legitimate
upload_progress usage, no spray — false-positive check).

**Should trigger** — which rule IDs from `rules/suricata.rules`,
`rules/sigma/`, or `rules/sentinel/` this sample is expected to fire (or, for
`benign`, expected *not* to fire).
