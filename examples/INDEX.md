# Sample index

| File | CVE | Path | Build | Outcome | Should trigger | Notes |
|------|-----|------|-------|---------|-----------------|-------|
| `pcaps/phpup2026-real-blob-CVE-109618-dtor0.pcap` | 109618 | `FILE_DATA stall` | n/a (dtor=0) | crash (null call addr) | `9109629`, `9109630` | 5-packet TCP session. src=`203.0.113.42`. Forged blob: IS_STRING_EX@+16, IS_OBJECT_EX@+160, `system\0id\0`@+200. `PHP_SESSION_UPLOAD_PROGRESS` + PHPSESSID present. No RCE (call_addr=0). |
| `pcaps/phpup2026-benign-legitimate-upload.pcap` | — | — | — | benign | `9109627` only | 6-packet session. src=`198.51.100.7`. Single `PHP_SESSION_UPLOAD_PROGRESS` field + PHPSESSID + small JPEG (~3.8KB). No spray, no zval markers, no dangerous function strings, body < 40KB. |
