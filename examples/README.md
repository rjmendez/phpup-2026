# examples/

Sanitized traffic and payload samples for validating the detection rules in `rules/`.

## Layout

```
examples/
  pcaps/   packet captures (.pcap/.pcapng)
  http/    single-request text dumps (headers + body)
  logs/    access-log / process-event snippets
  INDEX.md  one row per sample
```

## Before committing

- **Redact.** Source IPs → RFC 5737 TEST-NET (`203.0.113.x`, `198.51.100.x`, `2001:db8::/32`). Hostnames → `*.example.invalid`. Strip session cookies, auth tokens, and command output not part of the PoC's own fixed strings.
- **Trim.** One request/response pair; no multi-MB pcaps.
- **Label.** Add a row to `INDEX.md`: CVE, path (timed stall vs. ruled-out END — see `ANALYSIS.md`), build/version, outcome (rce / crash / benign).
- **Negative samples.** Legitimate `session.upload_progress` usage (no spray) validates that generic rules don't false-positive — mark as benign in `INDEX.md`.

Each rule in `rules/` should have at least one positive sample and one benign sample. A mismatch between sample and expected trigger is a bug in the rule or the sample — file it.
