// phpup-2026 - YARA rules
// CVE-2026-109618 / CVE-2026-109619 · PHP longjmp/bailout state corruption · RCE
//
// 2026-10-21 rewrite. `phpup2026_spray` is removed, not caveated: it
// matched a forged zend_fcall_info byte layout (IS_STRING_EX@+16,
// IS_OBJECT_EX@+160, system\0@+200) that came entirely from the leaked
// PoC artifact's own code, not from the real fix (php/php-src commit
// 82f8f31b16a). VulnCheck independently reports that none of the public
// PoCs they reviewed have the correct mechanism for this CVE pair, and
// this repo's own lab never produced a working crash/RCE under that
// layout's documented trigger -- see ANALYSIS.md. A rule matching that
// byte layout detects this one artifact's own (likely non-functional)
// claim, not the vulnerability class.
//
// `phpup2026_source`/`phpup2026_distribution` are unaffected -- they
// fingerprint the artifact/tool itself (disk/memory forensics: "is this
// specific leaked PoC present"), a different use case from network
// detection of the real vulnerability, and don't depend on whether the
// artifact's own exploitation claims are accurate.

// Framework or PoC source file - matches poc0, poc1, php_up_framework, derivatives.
rule phpup2026_source : tool {
    meta:
        cves = "CVE-2026-109618,CVE-2026-109619"
        date = "2026-10-21"
        note = "fingerprints the leaked PoC artifact on disk/in memory; does not confirm the artifact's own claimed mechanism is correct"
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

// Artifact distribution reference - URL, hash, or author credit in any file.
rule phpup2026_distribution : artifact {
    meta:
        cves   = "CVE-2026-109618,CVE-2026-109619"
        date   = "2026-10-21"
        sha256 = "0c254d547cac650bfbcb2275e30c2083737520a51a0511646f1fbb7ed60a0d63"
    strings:
        $url  = "jackalsyn.com/posts/phpupAssets/php-up-2026.tar.gz"
        $hash = "0c254d547cac650bfbcb2275e30c2083737520a51a0511646f1fbb7ed60a0d63"
        $auth = "J4ck3LSyN"
    condition:
        any of them
}
