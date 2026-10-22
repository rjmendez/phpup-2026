# Hardening guide - CVE-2026-109618 / CVE-2026-109619

> **2026-10-21 rewrite.** An earlier revision of this file treated the two
> CVEs as unrelated and covered only CVE-2026-109619, based on the leaked
> PoC artifact's own (incorrect) mechanism claims. Both CVEs are fixed by
> the same `php/php-src` commit (`82f8f31b16a`, "Avoid state corruption via
> bailout") and share the same root-cause class - a `longjmp`-based
> "bailout" that can skip cleanup code and leave worker-persistent global
> state dangling for a later request on the same worker to read. See
> `ANALYSIS.md` for the full mechanism writeup. This guide now covers both
> together.

Defense-in-depth, ordered by impact. Apply every layer that fits your
deployment - no single layer here is a complete fix; only patching is.

---

## Layer 1 - Eliminate the attack surface

**Primary mitigation: patch.**

```
PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 - released 2026-10-21, fixes both CVEs.
```

PHP 5/6/7 are EOL and will not be patched. PHP 8.1 and older get no fix
from the PHP project (source-only backports exist for 7.4/8.0/8.1 - the
8.0 backport disables the `session.upload_progress` consumer path
outright rather than backport the full fix; check with your distro/LTS
vendor for further backports).

**No complete generic configuration mitigation exists** per the PHP
advisory. The confirmed partial mitigations, all of which must be set in
`php.ini`, an FPM pool, or server config applied *before* request parsing
- not via `ini_set()` or FPM `.user.ini`, which apply too late - followed
by a restart of every worker:

```ini
; closes the confirmed session.upload_progress consumer path (CVE-2026-109619)
session.upload_progress.enabled = 0

; PHP 8.5 only - closes the strongest confirmed producer path (CVE-2026-109619)
fatal_error_backtraces = 0

; reduces exposure to the confirmed OOM producer trigger (CVE-2026-109618):
; lock the memory limit so no pool/app override reintroduces a finite
; limit that can fail mid-request. Set via php_admin_value, not php_value.
memory_limit = -1
post_max_size = 8M        ; 32M if the app needs file uploads
upload_max_filesize = 8M  ; must stay below post_max_size
```

Also:
- Remove invalid/deprecated settings applied per request that emit
  diagnostics before initialization - `error_reporting`, `display_errors`,
  or `@` do not help; they hide the diagnostic without closing the gap.
- Fix attacker-reachable fatal errors and execution timeouts, including
  failures in callbacks, upload or import processing, and cleanup.
- Use a container/cgroup memory limit as an availability boundary, with a
  policy that kills only the affected worker. **Do not** use `RLIMIT_AS`
  or `RLIMIT_DATA` instead - those can themselves trigger the vulnerable
  allocation-failure path.

### New: prevent worker reuse

Derived directly from the real mechanism (not in the prior revision of
this file): the vulnerability requires a *later, different request* to
land on the *same worker process* a prior request left corrupted. If no
worker ever serves a second request, that consumer step is structurally
impossible.

```ini
; php-fpm pool config - kill and respawn the worker after every request
pm = static
pm.max_requests = 1
```

```apache
# Apache mod_php / prefork equivalent
MaxConnectionsPerChild 1
```

This has an obvious, significant performance cost (no worker reuse at
all) and is not a substitute for patching - treat it as a short-term
circuit-breaker for a high-value target you can't patch immediately, not
a standing configuration.

---

## Layer 2 - Break the exploit chain (defense-in-depth)

If a RCE chain does get reached, disabling dangerous functions stops it
at the call regardless of how the UAF was triggered or what reclaimed
the freed memory:

```ini
disable_functions = system,exec,shell_exec,passthru,popen,proc_open,
                    pcntl_exec,pcntl_fork,posix_mkfifo,posix_setuid,
                    posix_setgid,pcntl_signal
```

`disable_functions` is `php.ini`-only - cannot be overridden by
`.htaccess` or `ini_set()`. Set in `php.ini` or the FPM pool's
`php_admin_value`.

**Custom session save handlers increase exploitability.** With
`session_set_save_handler()` or `session.save_handler=user`, arbitrary
PHP executes inside `php_session_initialize()`. If you use
Redis/Memcached sessions:
- Audit whether `session.upload_progress.enabled` can simply be `0`.
- If not, lock the pool to the file handler for PHP endpoints that
  accept uploads: `php_admin_value[session.save_handler] = files`

---

## Layer 3 - Process isolation (limit post-RCE impact)

### php-fpm pool hardening

```ini
; Dedicated low-privilege user - not shared www-data
user  = php-app
group = php-app

; Chroot the worker (requires DocumentRoot under chroot path)
chroot = /srv/php-app/chroot

; Restrict writable paths
php_admin_value[open_basedir] = /srv/php-app/public:/tmp:/var/lib/php/sessions

; Prevent privilege escalation
php_admin_flag[allow_url_fopen]  = off
php_admin_flag[allow_url_include] = off
```

### AppArmor (Ubuntu/Debian)

A minimal profile for `/usr/sbin/php-fpm8.4` that blocks `execve`:

```
/usr/sbin/php-fpm8.4 {
  #include <abstractions/base>
  #include <abstractions/php>
  /srv/php-app/**   rw,
  /tmp/**           rw,
  /var/lib/php/sessions/** rw,
  deny /bin/**      x,
  deny /usr/bin/**  x,
  deny /usr/local/bin/** x,
  deny /proc/**     rw,
  deny /sys/**      rw,
}
```

### seccomp (systemd)

In the php-fpm systemd unit override (`/etc/systemd/system/php8.4-fpm.service.d/hardening.conf`):

```ini
[Service]
SystemCallFilter = ~execve execveat fork vfork clone
NoNewPrivileges  = yes
PrivateTmp       = yes
ProtectSystem    = strict
ReadWritePaths   = /var/lib/php/sessions /tmp /srv/php-app/uploads
ProtectHome      = yes
CapabilityBoundingSet =
```

### LiteSpeed / lsphp

```xml
<!-- httpd_config.conf per-vhost -->
<extProcessor lsphp82>
  extType  lsapi
  address  uds://tmp/lshttpd/lsphp.sock
  maxConns 35
  initTimeout 60
  retryTimeout 0
  persistConn 1
  respBuffer 0
  autoStart 1
  path     /usr/local/lsws/lsphp82/bin/lsphp
  backlog  100
  instances 35
  priority 0
  memSoftLimit   2047M
  memHardLimit   2047M
  procSoftLimit  400
  procHardLimit  500
  extUser  php-app
  extGroup php-app
</extProcessor>
```

Set `extUser`/`extGroup` to a dedicated account, not `nobody` or `apache`.

---

## Layer 4 - Web server / network controls

### Multipart request limits

2026-10-21: the prior revision of this section sized these limits around
the (now-retired) spray mechanism's claimed 50-70 KB body. The real,
fix-confirmed amplification vector is **header count per multipart
part**, not overall body size - `main/rfc1867.c` previously saved every
header line in a part unconditionally; a single part with an unbounded
number of headers costs far more memory inside PHP than on the wire.
Limit what you can at the web server/proxy layer:

```nginx
# nginx - general hygiene; does not by itself cap headers-per-part
location ~ \.php$ {
    client_max_body_size 8m;   # tune to your real max legitimate upload
}
```

```apache
LimitRequestBody 8388608
```

Most web servers/proxies don't have a dedicated "max headers per
multipart part" knob - if yours does (a capable WAF/ModSecurity rule
set, or an L7 proxy with MIME-aware inspection), use it. Otherwise this
is a real coverage gap this repo hasn't closed; `rules/suricata.rules`'s
duplicate/density signals are the best currently-available mitigation at
the network layer, with the caveats documented there.

### Block the field/feature at the edge - config snippets for SAPIs
this guide didn't cover before

2026-10-21: adapted from `eness/php2shell-CVE-2026-109618-CVE-2026-109619-PoC`
(a public, independently-authored repo - its own claimed RCE mechanism
and "source patch" do not match the real PHP fix, see `ANALYSIS.md`'s
"A wrong theory went public," but these config-only snippets work
regardless of which mechanism theory is correct, since they just stop
`session.upload_progress`/multipart reaching PHP at all).

**ModSecurity** (any Apache/nginx deployment with the module) - block
the field directly:

```apache
SecRequestBodyAccess On
SecRule ARGS_NAMES "@streq PHP_SESSION_UPLOAD_PROGRESS" \
    "id:1026109618,phase:2,t:none,deny,status:403,log,\
    msg:'PHP_SESSION_UPLOAD_PROGRESS field blocked (CVE-2026-109618/109619)'"
```

**Apache, no ModSecurity** - block multipart POST/PUT/PATCH at
directories that don't need uploads, via `.htaccess` or a `<Directory>`
block:

```apache
RewriteEngine On
RewriteCond %{REQUEST_METHOD} ^(POST|PUT|PATCH)$ [NC]
RewriteCond %{HTTP:Content-Type} ^[[:space:]]*multipart/form-data([;,[:space:]]|$) [NC]
RewriteRule ^ - [F,L]
```

**Lighttpd** - same idea, Lighttpd config syntax:

```lighttpd
$HTTP["request-method"] =~ "^(POST|PUT|PATCH)$" {
    $REQUEST_HEADER["Content-Type"] =~ "(?i)^\s*multipart/form-data([;,[:space:]]|$)" {
        url.access-deny = ( "" )
    }
}
```

**FrankenPHP** (Caddy-based) - disable the feature globally in the
Caddyfile, same `php.ini` directive as everywhere else:

```caddyfile
{
    frankenphp {
        php_ini session.upload_progress.enabled 0
    }
}
```

### Rate-limit multipart POST

```nginx
limit_req_zone $binary_remote_addr zone=uploads:10m rate=5r/m;
location ~ \.php$ {
    limit_req zone=uploads burst=3 nodelay;
}
```

### Block `PHP_SESSION_UPLOAD_PROGRESS` at the proxy

If your app doesn't use PHP's built-in upload progress at all, strip the field
before it reaches PHP:

```nginx
# nginx - remove the header at the proxy edge
# Requires lua-nginx or a WAF; simpler: block via ModSecurity / NAXSI rule:
SecRule REQUEST_BODY "@contains PHP_SESSION_UPLOAD_PROGRESS" \
    "id:1000001,phase:2,deny,status:403,msg:'phpup-2026 upload-progress trigger'"
```

### Egress filtering

```bash
# iptables - drop outbound from php-app user except to known services
iptables -A OUTPUT -m owner --uid-owner php-app -d 10.0.0.0/8 -j ACCEPT
iptables -A OUTPUT -m owner --uid-owner php-app -j DROP
```

```
# pf (OPNsense/FreeBSD) - block outbound from webserver
block out quick on egress inet from <webserver_host> to ! <trusted_destinations>
```

---

## Layer 5 - Session hardening

```ini
session.cookie_httponly   = 1    ; blocks JS from reading PHPSESSID
session.cookie_secure     = 1    ; HTTPS only
session.cookie_samesite   = Lax  ; CSRF reduction
session.use_strict_mode   = 1    ; reject unrecognized session IDs
session.gc_maxlifetime    = 900  ; shorter session lifetime
session.sid_length        = 48   ; longer SID (more entropy)
session.sid_bits_per_character = 6
```

None of these address the bailout/state-corruption mechanism directly;
they're general session-security hygiene worth having regardless.

---

## Layer 6 - Detection

Detections are in `rules/` - see `ANALYSIS.md` and `README.md`'s
"Detection philosophy" for what these actually cover and the honest
limits (the cross-request "same worker" condition isn't visible from
any of these log sources).

| Format | File | Notes |
|--------|------|-------|
| Suricata 7+ | `rules/suricata.rules` | Feature-presence (9109627) + OOM-amplification signal (9109633) + php_up_framework tool fingerprint (9109637) - all live-fire verified against real attack captures and real legitimate traffic (including a real array-field stress test for 9109637) - 9109634/9109635/9109636 retired, see the file's own retired-rules section for why |
| YARA 4+ | `rules/yara.yar` | Source/distribution fingerprint only - the old spray-blob rule is retired |
| Sigma | `rules/sigma/` | Feature-presence, IDS-correlation (maps the new Suricata SIDs), process-spawn |
| Sentinel KQL | `rules/sentinel/phpup2026.kql` | Feature-presence, process-spawn - the OOM-amplification/hunting queries this once had were retired 2026-10-21 (AzureDiagnostics has no raw-request-body field; not fixable, see the file's header comment) |

Additional monitoring worth enabling:

```bash
# auditd - execve by web process user
-a always,exit -F arch=b64 -S execve -F uid=php-app -k php-rce

# php-fpm slow log
; www.conf
slowlog             = /var/log/php-fpm/slow.log
request_slowlog_timeout = 2s

# Watch session directory for upload_progress_ keys
inotifywait -m /var/lib/php/sessions -e create | \
    grep --line-buffered 'upload_progress_'

# PHP error log - watch for OOM / fatal-error entries on upload-accepting
# endpoints; the producer request may be invisible at the HTTP layer
# (see ANALYSIS.md's "What we have NOT reproduced") but should still log
grep -i "allowed memory size\|out of memory\|fatal error" /var/log/php*/error.log
```

---

## Quick-check priority order

1. **Patch PHP** - 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 (2026-10-21), fixes both CVEs
2. `session.upload_progress.enabled = 0` + `fatal_error_backtraces = 0` (PHP 8.5)
3. `memory_limit = -1` (admin-locked) + `post_max_size`/`upload_max_filesize`
4. If unpatchable short-term: `pm.max_requests = 1` / `MaxConnectionsPerChild 1`
5. `disable_functions` includes `system,exec,shell_exec,passthru,popen`
6. Dedicated process user + `seccomp`/AppArmor `execve` block
7. Egress filter from web server process
8. Load the Suricata/Sentinel rules at the edge - know their real coverage limits first
