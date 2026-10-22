#!/usr/bin/env python3
"""Minimal real-condition evaluator for rules/sentinel/phpup2026.kql and
rules/sentinel/analytics-rules/phpup2026-PHPShellSpawn.yaml's `query:` blocks.

Not a KQL engine -- hand-encodes the handful of operators this repo's
queries actually use (==, has, matches regex, in~, has_any) against
plain Python dicts, run against real field values translated from this
repo's own real captures (examples/logs/phpup2026-sysmonlinux-*.log for
the process-spawn queries, examples/logs/phpup2026-nginx-*.log for the
W3CIISLog query) plus one clearly-labeled constructed case where no real
capture exists (CommonSecurityLog -- this repo never built a WAF lab).

There is no live Azure Log Analytics workspace available to actually
execute this KQL, so this is schema/logic verification against real
field values, the same honesty standard already applied where a live
engine wasn't reachable (see rules/sentinel/phpup2026.kql's own header
comment on why requestBody_s-based queries were retired instead of
"probably fine").

Usage: python3 scripts/kql_eval.py
"""
import re


def has(s, sub):
    return sub in s


def matches_regex(s, pattern):
    return re.match(pattern, s, re.IGNORECASE) is not None


def in_ci(s, options):
    return s.lower() in {o.lower() for o in options}


def has_any(s, options):
    return any(o in s for o in options)


def t1_1(ev):
    if ev["csMethod"] != "POST":
        return False
    return has(ev["csCookie"], "PHPSESSID=") or has(ev["csUriQuery"], "PHP_SESSION_UPLOAD_PROGRESS")


def t1_2(ev):
    if ev["RequestMethod"] != "POST":
        return False
    return has(ev["Message"], "PHP_SESSION_UPLOAD_PROGRESS") and has(ev["Message"], "PHPSESSID=")


def t3_1(ev):
    if not matches_regex(ev["InitiatingProcessFileName"], r"^(php-fpm[\d.]*|php[\d.]*|lsphp[\d]*|apache2|httpd|nginx)$"):
        return False
    return in_ci(ev["FileName"], ["sh", "bash", "dash", "zsh", "ash", "python", "python2", "python3", "perl", "curl", "wget", "nc", "ncat", "nmap"]) \
        or has_any(ev["ProcessCommandLine"], ["/bin/sh", "/bin/bash", "bash -i", "python -c", "exec(", "eval("])


def t3_2(ev):
    if not has_any(ev["SubjectUserName"], ["www-data", "apache", "nobody", "lsphp", "iis apppool"]):
        return False
    return in_ci(ev["NewProcessName"], ["sh", "bash", "dash", "zsh", "ash", "python", "python2", "python3", "curl", "wget", "nc", "ncat", "nmap"]) \
        or has_any(ev["CommandLine"], ["/bin/sh", "/bin/bash", "bash -i", "python -c"])


def phpshellspawn(ev):
    if not matches_regex(ev["InitiatingProcessFileName"], r"^(php-fpm[\d.]*|php[\d.]*|lsphp[\d]*|apache2|httpd)$"):
        return False
    return in_ci(ev["FileName"], ["sh", "bash", "dash", "zsh", "ash", "python", "python2", "python3", "perl", "ruby", "curl", "wget", "nc", "ncat", "nmap", "whoami", "id"]) \
        or has_any(ev["ProcessCommandLine"], ["/bin/sh", "/bin/bash", "bash -i", "python -c", "python3 -c", "exec(", "eval(", "base64 -d", "curl ", "wget "])


def run(name, fn, ev, label, expect):
    result = fn(ev)
    status = "OK" if result == expect else "MISMATCH (expected %s)" % expect
    print(f"[{name}] event={label} -> {'MATCH' if result else 'no match'}  [{status}]")
    return result == expect


if __name__ == "__main__":
    all_ok = True

    print("=== T1-1 (W3CIISLog) ===")
    # Real capture: examples/logs/phpup2026-nginx-benign-upload-progress.log
    benign_real = {"csMethod": "POST", "csCookie": "PHPSESSID=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", "csUriQuery": ""}
    # Real capture: examples/logs/phpup2026-nginx-stall-no-crash.log
    stall_real = {"csMethod": "POST", "csCookie": "PHPSESSID=d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9", "csUriQuery": ""}
    no_cookie_constructed = {"csMethod": "POST", "csCookie": "", "csUriQuery": ""}
    all_ok &= run("T1-1", t1_1, benign_real, "benign (real)", True)
    all_ok &= run("T1-1", t1_1, stall_real, "stall (real)", True)
    all_ok &= run("T1-1", t1_1, no_cookie_constructed, "no cookie (CONSTRUCTED negative control)", False)

    print("\n=== T1-2 (CommonSecurityLog) -- CONSTRUCTED, no real WAF capture exists in this repo ===")
    t12_positive_constructed = {"RequestMethod": "POST", "Message": "...PHP_SESSION_UPLOAD_PROGRESS=x...PHPSESSID=abc..."}
    t12_negative_constructed = {"RequestMethod": "POST", "Message": "...ordinary request, no session fields..."}
    all_ok &= run("T1-2", t1_2, t12_positive_constructed, "CONSTRUCTED positive", True)
    all_ok &= run("T1-2", t1_2, t12_negative_constructed, "CONSTRUCTED negative", False)

    print("\n=== T3-1 (DeviceProcessEvents) ===")
    # Real capture: examples/logs/phpup2026-sysmonlinux-shell-spawn.log
    # (ParentImage: /usr/sbin/php-fpm8.3 -> InitiatingProcessFileName is
    # the basename, "php-fpm8.3"; Image: /bin/dash -> FileName "dash")
    shell_spawn_real = {"InitiatingProcessFileName": "php-fpm8.3", "FileName": "dash",
                         "ProcessCommandLine": '/bin/sh -c "id; whoami; sleep 1.5"'}
    # Real capture: examples/logs/phpup2026-sysmonlinux-benign-cron-fp.log
    # (ParentImage: /usr/sbin/cron -> InitiatingProcessFileName "cron",
    # which does NOT match the parent regex at all)
    cron_fp_real = {"InitiatingProcessFileName": "cron", "FileName": "dash",
                     "ProcessCommandLine": "/bin/sh -c /opt/app/bin/nightly-backup.sh"}
    all_ok &= run("T3-1", t3_1, shell_spawn_real, "real shell_exec() spawn", True)
    all_ok &= run("T3-1", t3_1, cron_fp_real, "real cron FP capture -- but NOT a false positive here", False)

    print("\n=== T3-2 (SecurityEvent 4688) ===")
    shell_spawn_real_sec = {"SubjectUserName": "www-data", "NewProcessName": "dash",
                             "CommandLine": '/bin/sh -c "id; whoami; sleep 1.5"'}
    cron_fp_real_sec = {"SubjectUserName": "www-data", "NewProcessName": "dash",
                         "CommandLine": "/bin/sh -c /opt/app/bin/nightly-backup.sh"}
    all_ok &= run("T3-2", t3_2, shell_spawn_real_sec, "real shell_exec() spawn (via CommandLine fallback)", True)
    all_ok &= run("T3-2", t3_2, cron_fp_real_sec, "real cron FP -- matches (documented FP, same as Sigma)", True)
    # Isolates the exact gap caught and fixed above: a shell invoked
    # directly as /bin/dash, with no "/bin/sh" substring anywhere in
    # CommandLine, so NewProcessName alone must carry it.
    dash_direct_constructed = {"SubjectUserName": "www-data", "NewProcessName": "dash", "CommandLine": '/bin/dash -c "id"'}
    all_ok &= run("T3-2", t3_2, dash_direct_constructed, "CONSTRUCTED: dash invoked directly, no /bin/sh substring -- isolates the fixed gap", True)

    print("\n=== PHPShellSpawn.yaml ===")
    all_ok &= run("PHPShellSpawn", phpshellspawn, shell_spawn_real, "real shell_exec() spawn", True)
    all_ok &= run("PHPShellSpawn", phpshellspawn, cron_fp_real, "real cron FP capture -- but NOT a false positive here", False)

    print()
    if all_ok:
        print("all checks OK")
    else:
        print("SOME CHECKS FAILED -- see MISMATCH lines above")
        raise SystemExit(1)
