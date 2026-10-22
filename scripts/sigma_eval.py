#!/usr/bin/env python3
"""Minimal real Sigma-condition evaluator for rules/sigma/*.yml.

Not a general-purpose Sigma engine -- only handles what this repo's 3
rules actually use: |contains / |gte / |re / |endswith field modifiers,
plain-equality list matching (for alert.signature_id), and conditions
of the shape "all of selection_*" or "(a or b) and c". No
aggregations/correlation.

2026-10-21 rewrite: the prior revision of this script tested a 4th rule,
phpup2026-upload-pattern.yml, and the old retired Suricata SIDs
(9109628-9109630) -- that file no longer exists (retired the same day
ANALYSIS.md was rewritten around the real fix commit) and those SIDs
were deleted from suricata.rules, so the old script was testing rules
that no longer exist. This version tests the 3 sigma rules that
currently ship, against real captured field values from examples/ where
real values exist, each one cited to its source file. Where no real
negative-control event exists in examples/ (feature-presence.yml's "no
PHPSESSID cookie" case), the event is clearly marked CONSTRUCTED, not
real, rather than silently presented as a lab capture.

Usage: python3 scripts/sigma_eval.py rules/sigma
"""
import sys
import yaml
import re


def match_value(event_val, cond_val, modifier):
    if event_val is None:
        return False
    s = str(event_val)
    if modifier == "contains":
        if isinstance(cond_val, list):
            return any(str(v) in s for v in cond_val)
        return str(cond_val) in s
    if modifier == "gte":
        try:
            return float(event_val) >= float(cond_val)
        except (TypeError, ValueError):
            return False
    if modifier == "re":
        return re.search(cond_val, s) is not None
    if modifier == "endswith":
        if isinstance(cond_val, list):
            return any(s.endswith(str(v)) for v in cond_val)
        return s.endswith(str(cond_val))
    # plain equality (used for alert.signature_id list and cs-method)
    if isinstance(cond_val, list):
        return event_val in cond_val or str(event_val) in [str(v) for v in cond_val]
    return str(event_val) == str(cond_val)


def eval_selection(sel, event):
    for field, cond_val in sel.items():
        if "|" in field:
            name, modifier = field.split("|", 1)
        else:
            name, modifier = field, "eq"
        ok = match_value(event.get(name), cond_val, modifier)
        if not ok:
            return False
    return True


def eval_condition(cond_str, selections):
    # Only patterns used by this repo's rules: "all of selection_*",
    # a bare selection name, or "(a or b) and c" style. Build a
    # python-evalable expr.
    if cond_str.strip() == "all of selection_*":
        return all(v for k, v in selections.items() if k.startswith("selection"))
    expr = cond_str
    for k in sorted(selections, key=len, reverse=True):
        expr = re.sub(rf"\b{k}\b", f"_r['{k}']", expr)
    return eval(expr, {}, {"_r": selections})


def run_rule(path, event, label, expect):
    rule = yaml.safe_load(open(path))
    det = rule["detection"]
    cond = det["condition"]
    selections = {k: eval_selection(v, event) for k, v in det.items() if k != "condition"}
    result = eval_condition(cond, selections)
    status = "OK" if result == expect else "MISMATCH (expected %s)" % expect
    print(f"[{rule['title']}] event={label} -> {'MATCH' if result else 'no match'}  [{status}]  (selections: {selections})")
    return result == expect


if __name__ == "__main__":
    base = sys.argv[1]  # path to rules/sigma dir
    all_ok = True

    print("=== feature-presence (9c4e6b31) ===")
    # Real capture: examples/logs/phpup2026-nginx-benign-upload-progress.log
    # (cs-method POST, cs-headers multipart/form-data;boundary=B1benign001,
    # cs-cookie PHPSESSID=a1b2c3d4...). Real alert: examples/logs/
    # phpup2026-eve-benign.json confirms sid 9109627 (this rule's only
    # live-fire-verified sibling) fired on this exact traffic.
    benign_real = {"cs-method": "POST",
                   "cs-headers": "multipart/form-data; boundary=B1benign001",
                   "cs-cookie": "PHPSESSID=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"}
    # Real capture: examples/logs/phpup2026-nginx-stall-no-crash.log. Real
    # alert: examples/logs/phpup2026-eve-stall-no-crash.json also confirms
    # 9109627 fired here.
    stall_real = {"cs-method": "POST",
                  "cs-headers": "multipart/form-data; boundary=B4stall004",
                  "cs-cookie": "PHPSESSID=d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9"}
    # CONSTRUCTED negative control -- no example in this repo captures a
    # multipart POST without a PHPSESSID cookie, so this is the benign
    # event's real fields with the cookie field removed, not a capture.
    no_cookie_constructed = {"cs-method": "POST",
                              "cs-headers": "multipart/form-data; boundary=B1benign001",
                              "cs-cookie": ""}
    all_ok &= run_rule(f"{base}/phpup2026-feature-presence.yml", benign_real, "benign (real)", expect=True)
    all_ok &= run_rule(f"{base}/phpup2026-feature-presence.yml", stall_real, "stall (real)", expect=True)
    all_ok &= run_rule(f"{base}/phpup2026-feature-presence.yml", no_cookie_constructed, "no PHPSESSID cookie (CONSTRUCTED negative control)", expect=False)

    print("\n=== process-spawn (4b9d2e51) ===")
    # Real capture: examples/logs/phpup2026-sysmonlinux-shell-spawn.log
    # (ParentImage included too -- the same real log line has both fields)
    shell_spawn_real = {"User": "www-data", "ParentCommandLine": "php-fpm: pool www",
                         "ParentImage": "/usr/sbin/php-fpm8.3",
                         "CommandLine": '/bin/sh -c "id; whoami; sleep 1.5"'}
    # Real capture: examples/logs/phpup2026-sysmonlinux-benign-cron-fp.log
    # -- documented, confirmed-live false positive (cron, not php-fpm, but
    # selection_user+selection_cmd still match on their own).
    cron_fp_real = {"User": "www-data", "ParentCommandLine": "/usr/sbin/cron -f -P",
                     "ParentImage": "/usr/sbin/cron",
                     "CommandLine": "/bin/sh -c /opt/app/bin/nightly-backup.sh"}
    all_ok &= run_rule(f"{base}/phpup2026-process-spawn.yml", shell_spawn_real, "real shell_exec() spawn", expect=True)
    all_ok &= run_rule(f"{base}/phpup2026-process-spawn.yml", cron_fp_real, "real cron FP (documented)", expect=True)
    # Isolate the new selection_parent_image check specifically: real
    # ParentImage (/usr/sbin/php-fpm8.3, versioned binary name) with NO
    # ParentCommandLine match and NO User match, to confirm the |re
    # pattern alone (not falling through to the other two selections)
    # correctly handles the version suffix against real data.
    parent_image_only_real = {"User": "someotheruser", "ParentCommandLine": "--daemonize --allow-to-run-as-root",
                               "ParentImage": "/usr/sbin/php-fpm8.3",
                               "CommandLine": "/bin/sh -c id"}
    all_ok &= run_rule(f"{base}/phpup2026-process-spawn.yml", parent_image_only_real, "real ParentImage (versioned php-fpm8.3), isolating selection_parent_image", expect=True)

    print("\n=== ids-correlation (6a2f8d14) ===")
    # Each Suricata alert is its own event (one signature_id each) -- a
    # sigma rule with no aggregation evaluates per event, not across a
    # batch.
    # sid 9109633: confirmed by live-fire re-verification (2026-10-21,
    # `suricata -S rules/suricata.rules -r <pcap> -k none`) to fire
    # exactly twice on examples/pcaps/phpup2026-real-oom-amplification.pcap
    # and twice on phpup2026-real-fpm-worker-recycle-85.pcap. Real, not
    # hypothetical.
    all_ok &= run_rule(f"{base}/phpup2026-ids-correlation.yml", {"alert.signature_id": 9109633}, "sid 9109633 (real, live-fire confirmed)", expect=True)
    # sid 9109627: real alert (fired on the benign and stall-no-crash
    # captures, see eve-benign.json/eve-stall-no-crash.json) but NOT in
    # this rule's selection list -- a real negative control, not
    # constructed: this rule should not fire on the feature-presence SID.
    all_ok &= run_rule(f"{base}/phpup2026-ids-correlation.yml", {"alert.signature_id": 9109627}, "sid 9109627 (real alert, wrong rule's SID -- negative control)", expect=False)
    # sid 9109634/9109635/9109636: retired, must NOT be in this rule's
    # selection list at all (not just "doesn't match this event" --
    # shouldn't be listed as a possibility). 9109635 was proven to
    # false-positive on a real legitimate 4-file upload (examples/pcaps/
    # phpup2026-real-legit-multifile-benign.pcap, examples/logs/
    # phpup2026-eve-legit-multifile-fp.json) -- not merely unexercised,
    # actually wrong. Confirmed by reading the YAML directly above; also
    # spot-checked here that none of the three ever match.
    all_ok &= run_rule(f"{base}/phpup2026-ids-correlation.yml", {"alert.signature_id": 9109634}, "sid 9109634 (retired SID, must not match)", expect=False)
    all_ok &= run_rule(f"{base}/phpup2026-ids-correlation.yml", {"alert.signature_id": 9109635}, "sid 9109635 (retired SID, proven false-positive, must not match)", expect=False)
    # sid 9109637: real, active, live-fire-verified SID (the
    # php_up_framework tool fingerprint) -- NOT retired, but
    # deliberately excluded from this rule's selection list, same
    # reasoning as the retired SIDs produce the same expected result
    # (no match) for a different reason: this rule's scope is the real
    # OOM-amplification/bailout mechanism specifically, and 9109637
    # makes a materially weaker, different claim ("this tool's output
    # was observed," not "the mechanism fired"). See this YAML's own
    # description for the full reasoning.
    all_ok &= run_rule(f"{base}/phpup2026-ids-correlation.yml", {"alert.signature_id": 9109637}, "sid 9109637 (real, active, deliberately excluded -- different claim, not retired)", expect=False)
    all_ok &= run_rule(f"{base}/phpup2026-ids-correlation.yml", {"alert.signature_id": 9109636}, "sid 9109636 (retired SID, must not match)", expect=False)

    print()
    if all_ok:
        print("all checks OK")
    else:
        print("SOME CHECKS FAILED -- see MISMATCH lines above")
        sys.exit(1)
