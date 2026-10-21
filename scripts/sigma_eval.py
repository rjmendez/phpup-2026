#!/usr/bin/env python3
"""Minimal real Sigma-condition evaluator for rules/sigma/*.yml.

Not a general-purpose Sigma engine -- only handles what this repo's 4
rules actually use: |contains / |gte field modifiers, plain-equality
list matching (for alert.signature_id), and conditions of the shape
"all of selection_*" or "(a or b) and c". No aggregations/correlation.

Hardcoded event dicts below are real values from this session's lab
capture (see examples/pcaps/, examples/logs/). This is how the real
cs-bytes|contains bug in feature-presence.yml and upload-pattern.yml
was found: cs-bytes is numeric and can never "contain" a field-name
string, so a real event with the real byte count correctly evaluates
to no-match there, exposing a selection clause that could never fire.

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


def run_rule(path, event, label):
    rule = yaml.safe_load(open(path))
    det = rule["detection"]
    cond = det["condition"]
    selections = {k: eval_selection(v, event) for k, v in det.items() if k != "condition"}
    result = eval_condition(cond, selections)
    print(f"[{rule['title']}] event={label} -> {'MATCH' if result else 'no match'}  (selections: {selections})")
    return result


if __name__ == "__main__":
    base = sys.argv[1]  # path to rules/sigma dir

    # Real event: oversized-spray capture (feature-presence + upload-pattern)
    oversized = {"cs-method": "POST", "cs-headers": "multipart/form-data; boundary=B2oversize002",
                 "cs-cookie": "PHPSESSID=b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7",
                 "cs-bytes": 58403}
    benign = {"cs-method": "POST", "cs-headers": "multipart/form-data; boundary=B1benign001",
              "cs-cookie": "PHPSESSID=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
              "cs-bytes": 4220}
    stall = {"cs-method": "POST", "cs-headers": "multipart/form-data; boundary=B4stall004",
             "cs-cookie": "PHPSESSID=d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9",
             "cs-bytes": 4547}

    print("=== feature-presence (9c4e6b31) ===")
    run_rule(f"{base}/phpup2026-feature-presence.yml", oversized, "oversized (real)")
    run_rule(f"{base}/phpup2026-feature-presence.yml", benign, "benign (real)")
    run_rule(f"{base}/phpup2026-feature-presence.yml", stall, "stall (real)")

    print("\n=== upload-pattern (7d9e1b23) ===")
    run_rule(f"{base}/phpup2026-upload-pattern.yml", oversized, "oversized (real) -- expect MATCH")
    run_rule(f"{base}/phpup2026-upload-pattern.yml", benign, "benign (real) -- expect no match")
    run_rule(f"{base}/phpup2026-upload-pattern.yml", stall, "stall (real) -- expect no match")

    print("\n=== process-spawn (4b9d2e51) ===")
    shell_spawn = {"User": "www-data", "ParentCommandLine": "php-fpm: pool www",
                   "CommandLine": '/bin/sh -c "id; whoami; sleep 1.5"'}
    cron_fp = {"User": "www-data", "ParentCommandLine": "/usr/sbin/cron -f -P",
               "CommandLine": "/bin/sh -c /opt/app/bin/nightly-backup.sh"}
    run_rule(f"{base}/phpup2026-process-spawn.yml", shell_spawn, "real shell_exec() spawn -- expect MATCH")
    run_rule(f"{base}/phpup2026-process-spawn.yml", cron_fp, "real cron FP -- expect MATCH (documented FP)")

    print("\n=== ids-correlation (6a2f8d14) ===")
    # Each Suricata alert is its own event (one signature_id each) -- a
    # sigma rule with no aggregation evaluates per event, not across a
    # batch. Test every real alert this lab actually produced.
    real_alert_events = [
        ("markers: 9109627", 9109627), ("markers: 9109629", 9109629), ("markers: 9109630", 9109630),
        ("benign: 9109627", 9109627),
        ("oversized: 9109627", 9109627), ("oversized: 9109628", 9109628),
        ("stall: 9109627", 9109627),
    ]
    for label, sid in real_alert_events:
        run_rule(f"{base}/phpup2026-ids-correlation.yml", {"alert.signature_id": sid}, label)
