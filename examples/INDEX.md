# Sample index

2026-10-21: four samples (two pcaps, two http dumps, two logs, two eve.json
entries) built around the retired single-request spray/byte-offset theory
were removed, not kept as "historical" -- they validated rule IDs
(9109628-9109632, sigma 7d9e1b23, YARA phpup2026_spray) that no longer
exist. See `ANALYSIS.md` for why. Two real captures from that era survive
below because they are still correct under the current understanding: the
benign control (still the false-positive check for the surviving rules)
and the stall-no-crash capture (which is *why* the old theory was
corrected in the first place -- good evidence, not bad data).

| File | CVE | Build | Outcome | Should trigger | Notes |
|------|-----|-------|---------|-----------------|-------|
| `pcaps/phpup2026-real-oom-amplification.pcap` | 109618 | real, PHP 8.3.6 (pre-patch, see note) | crash (256M) then survives (512M) then benign | `9109633`/`9109634` (crash case), `9109627` (all three) | **Real capture, 2026-10-21.** Three requests in one pcap: (1) 1.4M duplicate 5-byte headers in one multipart part, `memory_limit=256M` -> 502, php-fpm `exited with code 70` + respawn; (2) same payload, `memory_limit=512M` -> 200, `memory_get_peak_usage(true)`=408MB (~58x the 7MB wire payload); (3) benign 16-byte file upload control on the same worker -> 200. Pre-patch build: distro default (`8.3.6-0ubuntu0.24.04.13`) already had the fix backported despite the version string; downgraded to `.12` to get a genuinely vulnerable build (confirmed via `zend_new_array_singleton` symbol absence). Paired with `logs/phpup2026-real-oom-amplification-phpfpm.log` (crash+respawn) and `-nginx-access.log` (502/200/200 sequence, matches `request_length=7000362`). |
| `pcaps/phpup2026-real-benign-upload-progress.pcap` | -- | real, PHP 8.3.6 | benign | sigma `9c4e6b31`, Suricata `9109627` only | **Real capture.** IPs redacted client `203.0.113.42` / server `192.0.2.10` (real lab was loopback 127.0.0.1; HTTP `Host:` header still literally reads `127.0.0.1:8080`, left unmodified rather than rewrite real captured bytes). Pairs with the `.http` dump and `eve-benign.json`. |
| `pcaps/phpup2026-real-stall-no-crash.pcap` | -- | real, PHP 8.3.6 | 200 OK, **not** a crash | none (negative result) | **Real capture.** Two-file upload with a genuine 2-second stall between parts -- the exact precondition the retired theory claimed triggers a UAF. Real result: clean `200 OK`, `request_time` ~2.00s, no crash. This capture is *why* `ANALYSIS.md` was corrected, not something the correction made obsolete -- keep it. |
| `http/phpup2026-real-benign-upload-progress.http` | -- | real, PHP 8.3.6 | benign | -- | Single-request raw dump, byte-identical to the matching pcap/nginx-log/eve.json. |
| `http/phpup2026-real-stall-no-crash.http` | -- | real, PHP 8.3.6 | 200 OK, not a crash | -- | Single-request raw dump of the full reassembled two-file body. The real ~2s pause between `file1` and `file2` happened as two separate TCP writes and isn't representable in a flat single-request dump -- see the matching `.pcap` for real inter-packet timing. |
| `logs/phpup2026-real-oom-amplification-phpfpm.log` | 109618 | real, PHP 8.3.6 (pre-patch) | crash + respawn | -- | **Real capture.** `child <pid> exited with code 70` immediately followed by a new child PID starting -- direct evidence of hard worker death, not graceful survival. |
| `logs/phpup2026-real-oom-amplification-nginx-access.log` | 109618 | real, PHP 8.3.6 (pre-patch) | 502, 200, 200 | -- | **Real capture.** Three lines matching the pcap's three requests; `cs-bytes`-equivalent field shows `7000362` for both the crash and survive requests (identical payload, different `memory_limit`). |
| `logs/phpup2026-nginx-benign-upload-progress.log` | -- | real, PHP 8.3.6 | benign | sigma `9c4e6b31`, Suricata `9109627` only | **Real capture**: real nginx+php-fpm 8.3.6 lab, real small (3.8KB) legitimate upload_progress request. See `phpup2026-eve-benign.json` for the real alert it produced. |
| `logs/phpup2026-nginx-stall-no-crash.log` | -- | real, PHP 8.3.6 | 200 OK, **not** a crash | none (negative result) | **Real capture.** Two-file upload with a genuine 2-second stall between parts. Real result: clean `200 OK`, `request_time` ~2.00s, no crash -- direct empirical evidence the retired theory's described bug doesn't occur, not just static analysis. |
| `logs/phpup2026-eve-benign.json` | -- | real, PHP 8.3.6 | benign | `9109627` only | **Real Suricata output**, against the real benign capture. SID 9109627 is unchanged across the 2026-10-21 rule rewrite, so this stays valid. |
| `logs/phpup2026-eve-stall-no-crash.json` | -- | real, PHP 8.3.6 | 200 OK, not a crash | `9109627` only | **Real Suricata output.** Compare the alert `timestamp` to the flow's `start` field -- the ~2.00s gap is the real stall. Only the baseline policy signal fires; nothing escalates, because nothing crashes. |
| `logs/phpup2026-sysmonlinux-shell-spawn.log` | -- | n/a (direct call, not post-RCE) | n/a | sigma `4b9d2e51`, KQL T3-1/T3-2 | **Real capture**: real PIDs/user from a live WSL process tree (`php-fpm8.3` pool `www` -> `sh` -> `sh`), captured via `/proc` polling and reformatted to Sysmon-for-Linux field style. Reached via a direct `shell_exec()` test endpoint, not the vulnerability -- generic post-exploitation indicator only, see `ANALYSIS.md`. |
| `logs/phpup2026-sysmonlinux-benign-cron-fp.log` | -- | -- | benign (documented FP) | sigma `4b9d2e51` fires -- expected FP | **Real capture**: a real `cron(8)` job spawning a real shell, caught live mid-execution. Confirms the documented false positive (`ParentImage` is `cron`, not `php-fpm`, but `selection_user`+`selection_cmd` still match) against a real process tree, not an assertion. |

**Still open**: a sample demonstrating CVE-2026-109619's actual cross-request
consumer step (a producer request whose worker *survives* with dangling
globals, consumed by a later request) -- not yet captured. The
oom-amplification sample above hard-crashes instead of surviving; see
`ANALYSIS.md`'s "What we have NOT reproduced."
