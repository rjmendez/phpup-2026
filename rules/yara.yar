// phpup-2026 — YARA rules
// CVE-2026-109618 / CVE-2026-109619 · PHP session.upload_progress UAF · RCE

// Forged zend_fcall_info blob in HTTP body or memory.
// spray: 149x 288-byte blobs; IS_STRING_EX@+16, IS_OBJECT_EX@+160, system\0@+200.
rule phpup2026_spray : exploit {
    meta:
        cve  = "CVE-2026-109618,CVE-2026-109619"
        date = "2026-10-21"
    strings:
        $ise = { 06 01 00 00 }          // IS_STRING_EX at blob+16
        $ioe = { 08 03 00 00 }          // IS_OBJECT_EX at blob+160
        $sys = "system\x00"             // command string at blob+200
        $ctx = "PHP_SESSION_UPLOAD_PROGRESS"
    condition:
        $sys and $ctx and $ise and $ioe
}

// Framework or PoC source file — matches poc0, poc1, php_up_framework, derivatives.
rule phpup2026_source : tool {
    meta:
        cve  = "CVE-2026-109618,CVE-2026-109619"
        date = "2026-10-21"
    strings:
        $b1 = "B7kQpoc618"
        $b2 = "B7kQpoc619"
        $u1 = "php2shell-109618"
        $u2 = "php2shell-109619"
        $s1 = "DELTA_CALL"
        $s2 = "zval_ptr_dtor"
        $s3 = "JACKALPOC"
        $s4 = "PHP_SESSION_UPLOAD_PROGRESS"
        $s5 = "zend_call_function"
        $s6 = "FILLUNIT"
    condition:
        4 of them
}

// Artifact distribution reference — URL, hash, or author credit in any file.
rule phpup2026_distribution : artifact {
    meta:
        cve    = "CVE-2026-109618,CVE-2026-109619"
        date   = "2026-10-21"
        sha256 = "0c254d547cac650bfbcb2275e30c2083737520a51a0511646f1fbb7ed60a0d63"
    strings:
        $url  = "jackalsyn.com/posts/phpupAssets/php-up-2026.tar.gz"
        $hash = "0c254d547cac650bfbcb2275e30c2083737520a51a0511646f1fbb7ed60a0d63"
        $auth = "J4ck3LSyN"
    condition:
        any of them
}
