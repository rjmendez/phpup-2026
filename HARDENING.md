# Hardening guide — CVE-2026-109618 / CVE-2026-109619

Defense-in-depth ordered by impact. Each layer is independent; apply all that fit
your deployment.

---

## Layer 1 — Eliminate the attack surface

**Primary mitigation.** Disables the vulnerable code path entirely.

```ini
; php.ini or .htaccess or per-pool php_admin_value
session.upload_progress.enabled = 0
```

Verify: `php -r "echo ini_get('session.upload_progress.enabled');"`  — must print `0`.

**Patch** to PHP 8.2.35+ / 8.4.5+. PHP 5/6/7 are EOL and will not be patched.

---

## Layer 2 — Break the exploit chain (defense-in-depth)

The exploit ends with a call to `system()`. Disabling dangerous functions makes
RCE impossible even if the UAF fires and the spray lands.

```ini
disable_functions = system,exec,shell_exec,passthru,popen,proc_open,
                    pcntl_exec,pcntl_fork,posix_mkfifo,posix_setuid,
                    posix_setgid,pcntl_signal
```

Note: `disable_functions` is php.ini-only — cannot be overridden by `.htaccess` or `ini_set()`. Set in php.ini or the fpm pool's `php_admin_value`.

**Custom session save handlers increase exploitability.** With `session_set_save_handler()` or `session.save_handler=user`,
arbitrary PHP executes inside `php_session_initialize()`, making the UAF stall
window more reliable. If you use Redis/Memcached sessions:

- Audit whether `session.upload_progress.enabled` can simply be `0`.
- If not, lock the pool to file handler for PHP endpoints that accept uploads:
  `php_admin_value[session.save_handler] = files`

---

## Layer 3 — Process isolation (limit post-RCE impact)

### php-fpm pool hardening

```ini
; Dedicated low-privilege user — not shared www-data
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

## Layer 4 — Web server / network controls

### Request size limits

The exploit body is 50–70 KB (149 × 320-byte blobs + headers). Setting a
tight limit on upload endpoints breaks the spray.

```nginx
# nginx — per-location on upload endpoints
location ~ \.php$ {
    client_max_body_size 1m;   # tune to your max legitimate upload
}
```

```apache
# Apache
LimitRequestBody 1048576
```

```
# LiteSpeed
maxReqBodySize  1M    # in MB, per vhost security settings
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
# nginx — remove the header at the proxy edge
# Requires lua-nginx or a WAF; simpler: block via ModSecurity / NAXSI rule:
SecRule REQUEST_BODY "@contains PHP_SESSION_UPLOAD_PROGRESS" \
    "id:1000001,phase:2,deny,status:403,msg:'phpup-2026 upload-progress trigger'"
```

### Egress filtering

```bash
# iptables — drop outbound from php-app user except to known services
iptables -A OUTPUT -m owner --uid-owner php-app -d 10.0.0.0/8 -j ACCEPT
iptables -A OUTPUT -m owner --uid-owner php-app -j DROP
```

```
# pf (OPNsense/FreeBSD) — block outbound from webserver
block out quick on egress inet from <webserver_host> to ! <trusted_destinations>
```

---

## Layer 5 — Session hardening

```ini
session.cookie_httponly   = 1    ; blocks JS from reading PHPSESSID
session.cookie_secure     = 1    ; HTTPS only
session.cookie_samesite   = Lax  ; CSRF reduction
session.use_strict_mode   = 1    ; reject unrecognized session IDs
session.gc_maxlifetime    = 900  ; shorter session lifetime
session.sid_length        = 48   ; longer SID (more entropy)
session.sid_bits_per_character = 6
```

---

## Layer 6 — Detection

Detections are in `rules/`:

| Format | File | Notes |
|--------|------|-------|
| Suricata 7+ | `rules/suricata.rules` | Tier-1: exact POC artifacts (private); Tier-2: payload markers; Tier-3: behavioral |
| YARA 4+ | `rules/yara.yar` | Spray blob, source, distribution reference |
| Sigma | `rules/sigma/` | 6 rules including process spawn and upload pattern |
| Sentinel KQL | `rules/sentinel/phpup2026.kql` | 12 queries for W3CIISLog, DeviceProcessEvents, AzureDiagnostics |

Additional monitoring worth enabling:

```bash
# auditd — execve by web process user
-a always,exit -F arch=b64 -S execve -F uid=php-app -k php-rce

# php-fpm slow log (stall >1.5s is a red flag)
; www.conf
slowlog             = /var/log/php-fpm/slow.log
request_slowlog_timeout = 2s

# Watch session directory for upload_progress_ keys
inotifywait -m /var/lib/php/sessions -e create | \
    grep --line-buffered 'upload_progress_'
```

---

## Quick-check priority order

1. **Patch PHP** — scheduled today (8.2.35+ / 8.4.5+)
2. `session.upload_progress.enabled = 0` if you can tolerate it
3. `disable_functions` includes `system,exec,shell_exec,passthru,popen`
4. Dedicated process user + `seccomp`/AppArmor `execve` block
5. Egress filter from web server process
6. Load Suricata rules on edge
