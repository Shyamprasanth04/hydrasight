"""
Remediation recommendation engine.

Maps detected finding names/CVEs to actionable remediation text.
Designed to be generically useful regardless of exploit outcome:
a report with only recon findings still gets useful remediation advice.

Future: replace static map with CVE database lookups or AI-generated guidance.
"""

from hydrasight.models.findings import Findings

# static remediation map
# Keys are lowercase substrings matched against finding names.
# Order matters: more specific entries should appear first.
_REMEDIATION_MAP: list[tuple[str, str, str]] = [
    (
        "ms17",
        "CRITICAL",
        "Apply MS17-010 patch (KB4012212). Disable SMBv1 protocol. "
        "Block TCP 139/445 at the perimeter firewall.",
    ),
    (
        "ms08",
        "CRITICAL",
        "Apply MS08-067 patch (KB958644). Migrate all Windows 2000/XP endpoints immediately.",
    ),
    (
        "anonymous ftp",
        "HIGH",
        "Disable anonymous FTP login. Migrate to SFTP with key-based authentication.",
    ),
    (
        "vsftpd",
        "CRITICAL",
        "Upgrade vsftpd to 3.0.5+. The 2.3.4 backdoor is publicly known and trivially exploitable.",
    ),
    (
        "proftpd",
        "HIGH",
        "Upgrade ProFTPd to latest stable. "
        "Disable mod_copy module if not required (CVE-2015-3306).",
    ),
    (
        "samba",
        "HIGH",
        "Upgrade Samba to 4.x. Disable the usermap_script option. "
        "Apply CVE-2007-2447 vendor patch.",
    ),
    (
        "drupal",
        "CRITICAL",
        "Update Drupal to a supported version immediately. "
        "Apply security advisories SA-CORE-2018-002 (CVE-2018-7600).",
    ),
    (
        "phpmyadmin",
        "HIGH",
        "Upgrade phpMyAdmin to latest stable. "
        "Restrict access by IP or move behind authentication proxy.",
    ),
    (
        "tomcat",
        "HIGH",
        "Change Tomcat manager credentials from defaults. "
        "Restrict /manager/html to localhost or VPN only.",
    ),
    (
        "libssh",
        "HIGH",
        "Upgrade libssh to 0.8.4+. CVE-2018-10933 allows authentication bypass on server mode.",
    ),
    (
        "distcc",
        "HIGH",
        "Disable distccd if not required, or restrict to trusted IPs. "
        "CVE-2004-2687 allows unauthenticated RCE.",
    ),
    (
        "unrealircd",
        "CRITICAL",
        "Replace UnrealIRCd 3.2.8.1 immediately - it contains a compiled-in backdoor. "
        "Download only from official sources with signature verification.",
    ),
    (
        "java rmi",
        "HIGH",
        "Disable Java RMI registry if not required. Apply latest JDK security patches.",
    ),
    (
        "smb",
        "MEDIUM",
        "Enable SMB signing: Set-SmbServerConfiguration -RequireSecuritySignature $true",
    ),
    (
        "ssl",
        "MEDIUM",
        "Disable SSLv2/SSLv3 and TLS 1.0/1.1. Enforce TLS 1.2+ with strong cipher suites.",
    ),
    (
        "default credential",
        "HIGH",
        "Change all default credentials immediately. Implement a credential management policy.",
    ),
    (
        "open redirect",
        "LOW",
        "Validate and whitelist redirect URLs server-side. "
        "Avoid using user-supplied input directly in redirects.",
    ),
    (
        "xss",
        "MEDIUM",
        "Apply output encoding for all user-controlled data in HTML context. "
        "Implement a Content Security Policy (CSP) header.",
    ),
    (
        "sql injection",
        "CRITICAL",
        "Use parameterised queries or prepared statements. "
        "Never concatenate user input into SQL strings.",
    ),
    (
        "directory listing",
        "LOW",
        "Disable directory listing in web server config. "
        "Ensure sensitive files are not world-readable.",
    ),
]


def build_recommendations(findings: Findings) -> list[tuple[str, str]]:
    """
    Return a list of (severity, remediation_text) tuples based on findings.

    Works for any engagement outcome - no exploitation required.
    Covers recon findings, CVE findings, credential findings, and web findings.
    """
    recs: list[tuple[str, str]] = []
    matched: set[str] = set()

    names = {v["name"].lower() for v in findings.vulns}

    for substring, severity, text in _REMEDIATION_MAP:
        if any(substring in name for name in names):
            if substring not in matched:
                matched.add(substring)
                recs.append((severity, text))

    if findings.hashes:
        recs.append(
            (
                "HIGH",
                f"Rotate all {len(findings.hashes)} compromised account credentials. "
                "Enable Credential Guard. Enforce MFA.",
            )
        )

    if any(c["kind"] == "cracked" for c in findings.credentials):
        recs.append(
            (
                "CRITICAL",
                "Cracked passwords detected - enforce 14+ char minimum, "
                "complexity requirements, and mandate a password manager.",
            )
        )

    if any(c["kind"] == "bruteforce" for c in findings.credentials):
        recs.append(
            (
                "HIGH",
                "Brute-forced credentials found. Enforce account lockout policies "
                "and consider adding MFA to all exposed services.",
            )
        )

    sensitive_paths = {"/admin", "/backup", "/config", "/.git", "/wp-admin"}
    found_paths = {d["path"].lower() for d in findings.dirs}
    if found_paths & sensitive_paths:
        recs.append(
            (
                "HIGH",
                "Sensitive web paths discovered. Restrict access to admin/backup/config "
                "paths with authentication and IP allowlisting.",
            )
        )

    if not recs:
        recs.append(
            (
                "INFO",
                "No critical findings detected. Maintain current patch level and "
                "continue regular vulnerability scanning.",
            )
        )

    return recs
