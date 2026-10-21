# examples/

Captured traffic and payload samples for CVE-2026-109618 / CVE-2026-109619,
kept small and sanitized. These exist to validate the detection rules in
`rules/` against real byte layouts — not as a raw-data dump.

## Layout

```
examples/
  pcaps/   full or trimmed packet captures (.pcap/.pcapng)
  http/    single-request text dumps (headers + body), easier to diff/grep than a pcap
  logs/    access-log / process-event snippets showing the behavioral signals
  INDEX.md  one row per sample: what it is, what it should trigger
```

## Before committing a sample

- **Redact.** Real source IPs -> an RFC 5737/3849 TEST-NET address
  (`203.0.113.x`, `198.51.100.x`, or `2001:db8::/32`). Real hostnames ->
  `*.example.invalid`. Any real session cookie, auth token, or command
  output that isn't part of the PoC's own fixed strings -> strip it.
- **Trim.** Prefer the smallest capture that still contains the full
  multipart body (one request/response pair). Don't commit a multi-MB pcap
  when a few KB around the request does the job — keeps `git clone` light
  and makes it fast to pull a specific chunk into a test.
- **Label, don't just drop the file.** Add a row to `INDEX.md` saying which
  CVE, which path (timed stall vs. ruled-out END path — see root repo
  `ANALYSIS.md`), build/version if known, and outcome (crash / RCE /
  benign-but-matches-precondition). A sample with no label is not usable
  for regression-testing the rules later.
- **Mark intent for samples that should *not* alert.** A capture of
  legitimate `session.upload_progress` usage (real progress-bar upload,
  no spray) is just as valuable as a positive — it's a false-positive
  check for the generic rules in `rules/`. Say so in `INDEX.md`.

## What these are for

Each generic rule in `rules/{suricata.rules,sigma/,sentinel/}` should have
at least one sample here it actually fires on, and ideally one benign
sample it doesn't. If a sample doesn't trip the rule it's supposed to
validate, that's a bug in the rule, the sample, or both — file it as
such rather than silently dropping the sample.
