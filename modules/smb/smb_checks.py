# ============================================================
# RECON-X | modules/smb/smb_checks.py
# Description: Generate Finding objects for SMB security issues
#              including SMBv1, signing, null sessions, EternalBlue
# ============================================================

import logging
from typing import Any, Dict, List

from engine.findings import Finding, Port

logger = logging.getLogger(__name__)

_ETERNAL_BLUE_CVE = "CVE-2017-0144"
_ETERNAL_BLUE_REF = "https://www.rapid7.com/db/modules/exploit/windows/smb/ms17_010_eternalblue/"


class SMBChecks:
    """Generate security findings from collected SMB information.

    Each check produces zero or one Finding objects based on the
    evidence gathered by SMBScanner.
    """

    def __init__(
        self,
        host: str,
        port: int,
        smb_info: Any,
        open_ports: List[Port],
    ) -> None:
        """Initialize SMBChecks.

        Args:
            host: Target IP or hostname.
            port: SMB port (445 or 139).
            smb_info: Populated SMBInfo object.
            open_ports: All open ports with nmap script output.
        """
        self.host = host
        self.port = port
        self.smb_info = smb_info
        self.open_ports = open_ports

    def run_all_checks(self) -> List[Finding]:
        """Run all SMB security checks and return findings.

        Returns:
            List of Finding objects.
        """
        findings: List[Finding] = []
        findings.extend(self._check_smbv1())
        findings.extend(self._check_signing())
        findings.extend(self._check_null_session())
        findings.extend(self._check_guest_access())
        findings.extend(self._check_eternal_blue())
        findings.extend(self._check_ms17010_nmap())
        findings.extend(self._check_remote_admin_share())
        findings.extend(self._check_shares_read_write_access())
        findings.extend(self._check_default_shares())
        findings.extend(self._check_users_enumerated())
        findings.extend(self._check_domain_info_disclosure())
        findings.extend(self._check_weak_password_policy())
        findings.extend(self._check_printers_found())
        findings.extend(self._check_sensitive_files_found())
        findings.extend(self._check_sensitive_shares())
        findings.extend(self._check_nmap_vuln_scripts())
        return findings

    def _check_smbv1(self) -> List[Finding]:
        """Check if SMBv1 protocol is enabled."""
        smb_ver = (self.smb_info.smb_version or "").upper()
        if "SMB1" not in smb_ver and "1.0" not in smb_ver:
            return []
        return [Finding(
            title="SMBv1 Protocol Enabled",
            severity="High",
            category="SMB",
            target=self.host,
            port=self.port,
            description=(
                "The target supports SMBv1, a legacy protocol with multiple known critical "
                "vulnerabilities including EternalBlue (MS17-010). SMBv1 should be disabled "
                f"on all modern systems. Detected version: {self.smb_info.smb_version}"
            ),
            evidence=f"SMB dialect reported: {self.smb_info.smb_version}\nOS: {self.smb_info.os_info}",
            remediation=(
                "Disable SMBv1 via PowerShell: Set-SmbServerConfiguration -EnableSMB1Protocol $false\n"
                "Or via Group Policy: Computer Configuration → Admin Templates → Network → Lanman Workstation"
            ),
            cve_ids=[],
            references=[
                "https://docs.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3",
                "https://support.microsoft.com/en-us/topic/how-to-detect-enable-and-disable-smbv1-smbv2-and-smbv3-in-windows-abc41e97-7c68-b7c9-7ea4-abcc66b7d7a6",
            ],
        )]

    def _check_signing(self) -> List[Finding]:
        """Check if SMB signing is required."""
        if self.smb_info.signing_required:
            return []
        return [Finding(
            title="SMB Signing Not Required",
            severity="Medium",
            category="SMB",
            target=self.host,
            port=self.port,
            description=(
                "SMB signing is not required on this server. Without mandatory signing, "
                "an attacker on the network could intercept and relay SMB authentication "
                "to other servers (SMB relay attack / NTLM relay attack)."
            ),
            evidence="SMB signing enforcement: Not Required",
            remediation=(
                "Enable SMB signing via Group Policy:\n"
                "Computer Configuration → Windows Settings → Security Settings → "
                "Local Policies → Security Options → 'Microsoft network server: Digitally sign communications (always)' = Enabled"
            ),
            references=[
                "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/microsoft-network-server-digitally-sign-communications-always",
            ],
        )]

    def _check_null_session(self) -> List[Finding]:
        """Check if anonymous (null) SMB session is allowed."""
        if not self.smb_info.null_session:
            return []
        share_list = ", ".join(s["name"] for s in self.smb_info.shares) if self.smb_info.shares else "none enumerated"
        return [Finding(
            title="SMB Null Session Allowed",
            severity="Critical",
            category="SMB",
            target=self.host,
            port=self.port,
            description=(
                "An anonymous (null session) SMB connection was successfully established. "
                "This allows unauthenticated enumeration of shares, users, and potentially "
                "sensitive file access without any credentials."
            ),
            evidence=f"Null session login succeeded.\nShares visible: {share_list}",
            remediation=(
                "Restrict null session access via Group Policy:\n"
                "Computer Configuration → Windows Settings → Security Settings → "
                "Local Policies → Security Options:\n"
                "- 'Network access: Restrict anonymous access to Named Pipes and Shares' = Enabled\n"
                "- 'Network access: Do not allow anonymous enumeration of SAM accounts' = Enabled"
            ),
            references=[
                "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-restrict-anonymous-access-to-named-pipes-and-shares",
            ],
        )]

    def _check_guest_access(self) -> List[Finding]:
        """Check if guest SMB login is allowed."""
        if not self.smb_info.guest_access:
            return []
        return [Finding(
            title="SMB Guest Access Enabled",
            severity="High",
            category="SMB",
            target=self.host,
            port=self.port,
            description=(
                "SMB guest login was accepted without a password. This allows any user "
                "on the network to browse shares, potentially access sensitive files, "
                "and gather information about the system without authentication."
            ),
            evidence="Guest login (username: guest, no password) succeeded via SMB.",
            remediation=(
                "Disable the Guest account via: net user guest /active:no\n"
                "Or via Local Security Policy: Security Settings → Local Policies → "
                "User Rights Assignment → 'Deny access to this computer from the network' → add Guest"
            ),
            references=[
                "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/accounts-guest-account-status",
            ],
        )]

    def _check_eternal_blue(self) -> List[Finding]:
        """Check for EternalBlue conditions (SMBv1 + old Windows)."""
        smb_ver = (self.smb_info.smb_version or "").upper()
        os_info = (self.smb_info.os_info or "").lower()

        has_smbv1 = "SMB1" in smb_ver or "1.0" in smb_ver
        old_windows = any(
            kw in os_info
            for kw in ("windows 7", "windows xp", "windows vista", "server 2008", "server 2003")
        )

        if not (has_smbv1 and old_windows):
            return []

        return [Finding(
            title="EternalBlue Conditions Detected",
            severity="Critical",
            category="SMB",
            target=self.host,
            port=self.port,
            description=(
                "This host appears to meet the conditions for the EternalBlue exploit "
                f"(MS17-010 / {_ETERNAL_BLUE_CVE}): SMBv1 is enabled and the OS is a "
                f"version known to be vulnerable ({self.smb_info.os_info}). "
                "EternalBlue allows unauthenticated remote code execution and was used "
                "in the WannaCry and NotPetya ransomware campaigns."
            ),
            evidence=(
                f"SMB version: {self.smb_info.smb_version}\n"
                f"OS info: {self.smb_info.os_info}\n"
                "NOTE: This is a detection of vulnerability conditions only, NOT active exploitation."
            ),
            remediation=(
                "1. Apply MS17-010 patch immediately (KB4012212 for Server 2008, KB4012215 for Win 7)\n"
                "2. Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false\n"
                "3. Block SMB at the perimeter firewall (ports 139, 445)\n"
                "4. Consider isolating this host until patched"
            ),
            cve_ids=[_ETERNAL_BLUE_CVE],
            cvss_score=9.8,
            references=[
                _ETERNAL_BLUE_REF,
                "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010",
                "https://nvd.nist.gov/vuln/detail/CVE-2017-0144",
            ],
        )]

    def _check_ms17010_nmap(self) -> List[Finding]:
        """Check nmap smb-vuln-ms17-010 script output."""
        for port in self.open_ports:
            script_out = port.scripts_output.get("smb-vuln-ms17-010", "")
            if script_out and "VULNERABLE" in script_out.upper():
                return [Finding(
                    title="MS17-010 Vulnerability (nmap confirmed)",
                    severity="Critical",
                    category="SMB",
                    target=self.host,
                    port=port.port_number,
                    description=(
                        "nmap's smb-vuln-ms17-010 script confirmed this host is vulnerable "
                        "to MS17-010 (EternalBlue). This allows unauthenticated remote code execution."
                    ),
                    evidence=f"nmap smb-vuln-ms17-010 output:\n{script_out}",
                    remediation=(
                        "Apply MS17-010 security patch immediately.\n"
                        "See: https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010"
                    ),
                    cve_ids=[_ETERNAL_BLUE_CVE],
                    cvss_score=9.8,
                    references=[
                        "https://nvd.nist.gov/vuln/detail/CVE-2017-0144",
                    ],
                )]
        return []

    def _check_remote_admin_share(self) -> List[Finding]:
        """Check if ADMIN$ share is accessible (remote admin)."""
        admin_share = next(
            (s for s in self.smb_info.shares if s.get("name", "").upper() == "ADMIN$"),
            None
        )
        if not admin_share or not admin_share.get("accessible"):
            return []

        return [Finding(
            title="Remote Admin Share Accessible (ADMIN$)",
            severity="Critical",
            category="SMB",
            target=self.host,
            port=self.port,
            description=(
                "The ADMIN$ hidden share is accessible without proper authentication. "
                "This share provides access to the system root directory (C:\\Windows\\system32) "
                "and allows attackers to deploy malware, modify system files, or completely "
                "compromise the system. This commonly indicates null session or guest access enabled."
            ),
            evidence=(
                f"ADMIN$ share is accessible.\n"
                f"Readable: {admin_share.get('readable', False)}\n"
                f"Writable: {admin_share.get('writable', False)}\n"
                f"Access type: {'Null session' if self.smb_info.null_session else 'Guest' if self.smb_info.guest_access else 'Unauthenticated'}"
            ),
            remediation=(
                "1. Disable null sessions and guest access immediately\n"
                "2. Enforce strong authentication for all SMB connections\n"
                "3. Restrict SMB access via firewall rules\n"
                "4. Use Group Policy to restrict access to administrative shares"
            ),
            cve_ids=[],
            references=[
                "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-restrict-anonymous-access-to-named-pipes-and-shares",
            ],
        )]

    def _check_shares_read_write_access(self) -> List[Finding]:
        """Check for shares with read and/or write access."""
        findings: List[Finding] = []
        
        readable_shares = [s for s in self.smb_info.shares if s.get("readable")]
        writable_shares = [s for s in self.smb_info.shares if s.get("writable")]

        # Report readable shares (excluding default IPC$ shares)
        non_ipc_readable = [s for s in readable_shares if not s.get("is_default_share")]
        if non_ipc_readable:
            share_names = ", ".join(s["name"] for s in non_ipc_readable)
            findings.append(Finding(
                title="Readable SMB Shares Enumerated",
                severity="Medium",
                category="SMB",
                target=self.host,
                port=self.port,
                description=(
                    f"The following SMB shares are readable without proper authentication: {share_names}. "
                    "Attackers can enumerate file system contents and potentially access sensitive data."
                ),
                evidence=(
                    f"Readable shares: {share_names}\n" +
                    "\n".join(f"  - {s['name']}: {len(s.get('files', []))} files" for s in non_ipc_readable)
                ),
                remediation=(
                    "1. Review and restrict share permissions\n"
                    "2. Enforce authentication for share access\n"
                    "3. Move sensitive data to more restricted locations\n"
                    "4. Apply the principle of least privilege"
                ),
            ))

        # Report writable shares (critical)
        if writable_shares:
            share_names = ", ".join(s["name"] for s in writable_shares)
            findings.append(Finding(
                title="Writable SMB Shares Detected",
                severity="Critical",
                category="SMB",
                target=self.host,
                port=self.port,
                description=(
                    f"The following SMB shares are writable without proper authentication: {share_names}. "
                    "This allows attackers to upload malware, modify files, create backdoors, "
                    "or conduct lateral movement attacks within the network."
                ),
                evidence=(
                    f"Writable shares: {share_names}\n" +
                    "\n".join(f"  - {s['name']}: WRITE ACCESS" for s in writable_shares)
                ),
                remediation=(
                    "1. Immediately restrict write access to all shares\n"
                    "2. Enable share permissions (everyone gets no write access by default)\n"
                    "3. Audit recent modifications to these shares\n"
                    "4. Investigate potential compromise or unauthorized changes"
                ),
                cve_ids=[],
            ))

        return findings

    def _check_default_shares(self) -> List[Finding]:
        """Check for default shares (IPC$, PRINT$, etc.) accessibility."""
        findings: List[Finding] = []
        
        default_shares_info = {
            "IPC$": "Named pipes used for remote administration",
            "PRINT$": "Print driver share",
            "C$": "Administrative share for C: drive",
            "D$": "Administrative share for D: drive",
            "E$": "Administrative share for E: drive",
        }
        
        for share in self.smb_info.shares:
            share_name = share.get("name", "").upper()
            if share_name in default_shares_info and share.get("readable"):
                severity = "High" if share_name.endswith("$") and share_name != "IPC$" else "Medium"
                
                findings.append(Finding(
                    title=f"Default Share Accessible: {share_name}",
                    severity=severity,
                    category="SMB",
                    target=self.host,
                    port=self.port,
                    description=(
                        f"The default share {share_name} is accessible. "
                        f"{default_shares_info.get(share_name, 'Description not available')}. "
                        "This should typically only be accessible to authenticated administrators."
                    ),
                    evidence=(
                        f"Share: {share_name}\n"
                        f"Accessible: True\n"
                        f"Readable: {share.get('readable', False)}\n"
                        f"Writable: {share.get('writable', False)}"
                    ),
                    remediation=(
                        "1. Restrict default share access via Group Policy\n"
                        "2. Disable unnecessary administrative shares\n"
                        "3. Enforce strong authentication for remote connections\n"
                        "4. Block SMB at the network perimeter"
                    ),
                ))

        return findings

    def _check_users_enumerated(self) -> List[Finding]:
        """Generate finding for enumerated users via RID cycling."""
        if not self.smb_info.users:
            return []

        user_names = [u.get("name") for u in self.smb_info.users if u.get("name")]
        user_list = ", ".join(user_names[:20])
        if len(user_names) > 20:
            user_list += f", ... and {len(user_names) - 20} more"

        return [Finding(
            title="Domain Users Enumerated via SMB",
            severity="High",
            category="SMB",
            target=self.host,
            port=self.port,
            description=(
                f"Successfully enumerated {len(user_names)} domain/local users via SMB RID cycling. "
                "This information can be used for password spraying, targeted phishing, or targeted attacks."
            ),
            evidence=(
                f"Users enumerated ({len(user_names)} total):\n{user_list}"
            ),
            remediation=(
                "1. Restrict RPC access via firewall/network ACLs\n"
                "2. Disable null session and guest access\n"
                "3. Enforce strong password policies\n"
                "4. Implement account lockout policies\n"
                "5. Monitor for RID cycling attempts"
            ),
            cve_ids=[],
        )]

    def _check_domain_info_disclosure(self) -> List[Finding]:
        """Generate finding for domain information disclosure."""
        findings: List[Finding] = []

        # Check for domain name disclosure
        if self.smb_info.domain and self.smb_info.domain.lower() not in ("workgroup", "mshome"):
            findings.append(Finding(
                title="Domain Information Disclosed via SMB",
                severity="Medium",
                category="SMB",
                target=self.host,
                port=self.port,
                description=(
                    f"The target is part of domain '{self.smb_info.domain}'. "
                    "Domain information can be used for targeted reconnaissance and attacks."
                ),
                evidence=(
                    f"Domain: {self.smb_info.domain}\n"
                    f"Computer: {self.smb_info.computer_name}\n"
                    f"OS: {self.smb_info.os_info}"
                ),
                remediation=(
                    "1. Restrict SMB access from untrusted networks\n"
                    "2. Use network segmentation to limit SMB exposure\n"
                    "3. Implement firewall rules to block SMB from external networks"
                ),
            ))

        # Check for computer name disclosure
        if self.smb_info.computer_name:
            findings.append(Finding(
                title="Computer Name Information Disclosed",
                severity="Low",
                category="SMB",
                target=self.host,
                port=self.port,
                description=(
                    f"Computer NetBIOS name '{self.smb_info.computer_name}' was disclosed via SMB. "
                    "This information helps attackers build a network map."
                ),
                evidence=(
                    f"Computer Name: {self.smb_info.computer_name}\n"
                    f"Domain Info: {self.smb_info.domain_info}"
                ),
                remediation=(
                    "1. Disable NetBIOS over TCP/IP if not required\n"
                    "2. Restrict SMB access at the perimeter"
                ),
            ))

        return findings

    def _check_weak_password_policy(self) -> List[Finding]:
        """Check for weak password policy settings."""
        findings: List[Finding] = []

        if not self.smb_info.password_policy:
            return []

        pwd_policy = self.smb_info.password_policy

        # Check minimum password length
        min_len = pwd_policy.get("min_password_length", 0)
        if min_len < 12:
            findings.append(Finding(
                title="Weak Password Length Policy",
                severity="High",
                category="SMB",
                target=self.host,
                port=self.port,
                description=(
                    f"The domain password policy requires a minimum of only {min_len} characters. "
                    "This is insufficient; modern standards recommend at least 12-14 characters."
                ),
                evidence=(
                    f"Minimum password length: {min_len} characters (policy)"
                ),
                remediation=(
                    "1. Increase minimum password length to at least 12 characters\n"
                    "2. Apply via Group Policy: Password Policy → Password must be at least X characters\n"
                    "3. Consider using passphrases instead of complex passwords"
                ),
            ))

        # Check password history
        pwd_hist = pwd_policy.get("password_history_length", 0)
        if pwd_hist < 12:
            findings.append(Finding(
                title="Weak Password History Policy",
                severity="Medium",
                category="SMB",
                target=self.host,
                port=self.port,
                description=(
                    f"Password history is set to only {pwd_hist} remembered passwords. "
                    "Users can cycle through old passwords quickly."
                ),
                evidence=(
                    f"Password history: {pwd_hist} passwords"
                ),
                remediation=(
                    "1. Increase password history to at least 12\n"
                    "2. Use Group Policy to enforce: Password Policy → Remember password history"
                ),
            ))

        return findings

    def _check_printers_found(self) -> List[Finding]:
        """Generate finding for discovered printers."""
        if not self.smb_info.printers:
            return []

        printer_names = [p.get("name") for p in self.smb_info.printers]
        printer_list = ", ".join(printer_names)

        return [Finding(
            title="Network Printers Discovered",
            severity="Low",
            category="SMB",
            target=self.host,
            port=self.port,
            description=(
                f"Discovered {len(self.smb_info.printers)} printer share(s) on the network. "
                "Printers often store credentials for authentication and can be compromised for lateral movement."
            ),
            evidence=(
                f"Printers found: {printer_list}"
            ),
            remediation=(
                "1. Restrict printer access via Group Policy\n"
                "2. Disable unnecessary printer shares\n"
                "3. Harden printer configurations (firmware updates, strong passwords)\n"
                "4. Implement network segmentation for printer access"
            ),
        )]

    def _check_sensitive_files_found(self) -> List[Finding]:
        """Generate findings for sensitive files discovered via recursive search."""
        if not self.smb_info.files_found:
            return []

        findings: List[Finding] = []
        
        # Group files by share
        files_by_share: Dict[str, List[str]] = {}
        for file_info in self.smb_info.files_found:
            share = file_info.get("share")
            path = file_info.get("path")
            if share not in files_by_share:
                files_by_share[share] = []
            files_by_share[share].append(path)

        # Generate findings for each share with sensitive files
        for share, files in files_by_share.items():
            file_list = ", ".join(files[:20])
            if len(files) > 20:
                file_list += f", ... and {len(files) - 20} more"

            findings.append(Finding(
                title=f"Sensitive Files Found in {share} Share",
                severity="High",
                category="SMB",
                target=self.host,
                port=self.port,
                description=(
                    f"Found {len(files)} sensitive files in share '{share}'. "
                    "These files commonly contain credentials, configurations, or other sensitive data."
                ),
                evidence=(
                    f"Share: {share}\n"
                    f"Files found ({len(files)} total):\n{file_list}"
                ),
                remediation=(
                    "1. Audit and remove unnecessary sensitive files from shares\n"
                    "2. Move sensitive files to restricted locations\n"
                    "3. Implement file-level encryption\n"
                    "4. Use DLP (Data Loss Prevention) solutions\n"
                    "5. Enforce strict access controls"
                ),
            ))

        return findings

    def _check_sensitive_shares(self) -> List[Finding]:
        """Generate findings for shares containing sensitive file patterns."""
        findings: List[Finding] = []
        for share in self.smb_info.shares:
            if share.get("sensitive_files"):
                sensitive = share["sensitive_files"]
                findings.append(Finding(
                    title="Sensitive Files Accessible via SMB",
                    severity="High",
                    category="SMB",
                    target=self.host,
                    port=self.port,
                    description=(
                        f"The SMB share '{share['name']}' is accessible and contains files "
                        f"matching sensitive file patterns: {', '.join(sensitive[:10])}"
                    ),
                    evidence=(
                        f"Share: {share['name']}\n"
                        f"Sensitive files found: {', '.join(sensitive)}\n"
                        f"Total files enumerated: {len(share.get('files', []))}"
                    ),
                    remediation=(
                        "1. Review share permissions and remove unnecessary access\n"
                        "2. Move sensitive files to properly secured locations\n"
                        "3. Implement the principle of least privilege for share access"
                    ),
                ))
        return findings

    def _check_nmap_vuln_scripts(self) -> List[Finding]:
        """Parse all nmap smb-vuln-* script outputs for vulnerabilities."""
        findings: List[Finding] = []

        # SMB vulnerability script mappings
        vuln_scripts = {
            "smb-vuln-ms17-010": {
                "title": "MS17-010 EternalBlue Vulnerability",
                "cve": "CVE-2017-0144",
                "severity": "Critical",
                "cvss": 9.8,
            },
            "smb-vuln-ms08-067": {
                "title": "MS08-067 NetAPI Vulnerability",
                "cve": "CVE-2008-4250",
                "severity": "Critical",
                "cvss": 10.0,
            },
            "smb-vuln-ms06-025": {
                "title": "MS06-025 RRAS Vulnerability",
                "cve": "CVE-2006-2370",
                "severity": "High",
                "cvss": 7.5,
            },
            "smb-vuln-ms07-029": {
                "title": "MS07-029 DNS RPC Vulnerability",
                "cve": "CVE-2007-1748",
                "severity": "High",
                "cvss": 9.3,
            },
            "smb-vuln-ms10-054": {
                "title": "MS10-054 SMB Client Trans2 Vulnerability",
                "cve": "CVE-2010-2550",
                "severity": "High",
                "cvss": 9.3,
            },
            "smb-vuln-ms10-061": {
                "title": "MS10-061 Print Spooler Vulnerability",
                "cve": "CVE-2010-2729",
                "severity": "High",
                "cvss": 9.0,
            },
            "smb-vuln-cve2009-3103": {
                "title": "SMBv2 Negotiation Vulnerability",
                "cve": "CVE-2009-3103",
                "severity": "High",
                "cvss": 10.0,
            },
            "smb-vuln-cve-2017-7494": {
                "title": "SambaCry Vulnerability",
                "cve": "CVE-2017-7494",
                "severity": "High",
                "cvss": 10.0,
            },
            "smb-vuln-conficker": {
                "title": "Conficker Worm Vulnerability",
                "cve": "CVE-2008-4250",
                "severity": "High",
                "cvss": 10.0,
            },
            "smb-vuln-regsvc-dos": {
                "title": "SMB Registry Service DoS",
                "cve": "CVE-2012-1182",
                "severity": "Medium",
                "cvss": 5.0,
            },
            "smb-vuln-webexec": {
                "title": "WebEx Service Remote Code Execution",
                "cve": "CVE-2018-0296",
                "severity": "High",
                "cvss": 8.3,
            },
            "smb2-vuln-uptime": {
                "title": "SMB2 Uptime Information Disclosure",
                "cve": None,
                "severity": "Low",
                "cvss": 2.1,
            },
        }

        for port in self.open_ports:
            for script_name, script_output in port.scripts_output.items():
                if script_name in vuln_scripts and "VULNERABLE" in script_output.upper():
                    vuln_info = vuln_scripts[script_name]
                    findings.append(Finding(
                        title=vuln_info["title"],
                        severity=vuln_info["severity"],
                        category="SMB",
                        target=self.host,
                        port=port.port_number,
                        description=(
                            f"nmap script {script_name} detected a vulnerability: {vuln_info['title']}. "
                            f"This could allow remote code execution, denial of service, or information disclosure."
                        ),
                        evidence=f"nmap {script_name} output:\n{script_output}",
                        remediation=(
                            f"Apply the appropriate security patch for {vuln_info['cve'] if vuln_info['cve'] else script_name}. "
                            "Check vendor security advisories and ensure the system is fully patched."
                        ),
                        cve_ids=[vuln_info["cve"]] if vuln_info["cve"] else [],
                        cvss_score=vuln_info["cvss"],
                        references=[
                            f"https://nvd.nist.gov/vuln/detail/{vuln_info['cve']}" if vuln_info["cve"] else
                            f"https://nmap.org/nsedoc/scripts/{script_name}.html"
                        ],
                    ))

        return findings
