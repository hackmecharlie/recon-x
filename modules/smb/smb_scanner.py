# ============================================================
# RECON-X | modules/smb/smb_scanner.py
# Description: SMB enumeration using impacket - comprehensive enumeration
#              including users, groups, policies, shares, permissions, etc.
# ============================================================

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from engine.findings import Finding, Port

logger = logging.getLogger(__name__)

_SENSITIVE_PATTERNS = re.compile(
    r"(web\.config|\.config|\.xml|passwords?\.txt|id_rsa|\.pem|\.pfx|\.kdbx|\.rdp|\.env|secret|credential|password|passwd|shadow|\.bak)$",
    re.IGNORECASE,
)


@dataclass
class SMBInfo:
    """Comprehensive SMB enumeration information for a target."""
    host: str
    # Version & Protocol Info
    smb_version: str = ""
    signing_required: bool = True
    dialect: str = ""
    security_mode: str = ""
    capabilities: Dict[str, Any] = field(default_factory=dict)
    
    # Host Information
    computer_name: str = ""
    computer_description: str = ""
    workgroup: str = ""
    domain: str = ""
    domain_info: Dict[str, Any] = field(default_factory=dict)
    
    # Authentication
    null_session: bool = False
    guest_access: bool = False
    remote_admin_access: bool = False
    
    # OS & System
    os_info: str = ""
    os_version: str = ""
    system_time: str = ""
    
    # Shares
    shares: List[Dict[str, Any]] = field(default_factory=list)
    printers: List[Dict[str, Any]] = field(default_factory=list)
    
    # Users & Groups
    users: List[Dict[str, Any]] = field(default_factory=list)
    groups: List[Dict[str, Any]] = field(default_factory=list)
    admins: List[str] = field(default_factory=list)
    
    # Policies
    password_policy: Dict[str, Any] = field(default_factory=dict)
    account_policy: Dict[str, Any] = field(default_factory=dict)
    
    # Additional Data
    files_found: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)


class SMBScanner:
    """Enumerate SMB services using impacket.

    Checks: version, signing, shares, null sessions, guest login,
    sensitive file patterns, and EternalBlue conditions.
    """

    def __init__(self, target: Any, open_ports: List[Port]) -> None:
        """Initialize SMBScanner.

        Args:
            target: Target object with ip and hostname.
            open_ports: List of open Port objects from nmap.
        """
        self.target = target
        self.host = target.ip or target.hostname or ""
        self.open_ports = open_ports
        self.port = 445 if any(p.port_number == 445 for p in open_ports) else 139

    def run(self) -> SMBInfo:
        """Execute all SMB checks and return structured results.

        Returns:
            SMBInfo with all collected data and findings list.
        """
        info = SMBInfo(host=self.host)

        try:
            self._enumerate_smb(info)
        except Exception as exc:  # noqa: BLE001
            logger.warning("SMB enumeration failed for %s: %s", self.host, exc)

        # Always run checks — they may detect via nmap data too
        from modules.smb.smb_checks import SMBChecks
        checker = SMBChecks(self.host, self.port, info, self.open_ports)
        info.findings.extend(checker.run_all_checks())

        return info

    def _enumerate_smb(self, info: SMBInfo) -> None:
        """Perform SMB enumeration using impacket.

        Args:
            info: SMBInfo to populate in-place.
        """
        try:
            from impacket.smbconnection import SMBConnection
            from impacket import smb, smb3
        except ImportError:
            logger.warning("impacket not installed — SMB enumeration skipped")
            return

        # ── Connect and detect version ─────────────────────────────────────
        conn: Optional[Any] = None
        try:
            conn = SMBConnection(self.host, self.host, sess_port=self.port, timeout=10)
            info.smb_version = conn.getServerNTLMChallenge() and "SMB2/3" or "SMB1"
            info.os_info = conn.getServerOS() or ""
            info.domain = conn.getServerDomain() or ""
            dialect = conn.getDialect()
            info.dialect = str(dialect)

            # Check signing
            try:
                info.signing_required = conn.isSigningRequired()
            except Exception:  # noqa: BLE001
                info.signing_required = True  # Assume required if unknown
        except Exception as exc:  # noqa: BLE001
            logger.debug("SMB version detection failed for %s: %s", self.host, exc)
            if conn:
                try:
                    conn.close()
                except Exception:  # noqa: BLE001
                    pass
            conn = None

        # ── Test null session ──────────────────────────────────────────────
        null_conn: Optional[Any] = None
        try:
            null_conn = SMBConnection(self.host, self.host, sess_port=self.port, timeout=10)
            null_conn.login("", "", "", "", "")  # null session
            info.null_session = True
            logger.info("SMB null session successful on %s", self.host)
            self._enumerate_shares(null_conn, info)
        except Exception:  # noqa: BLE001
            info.null_session = False
        finally:
            if null_conn:
                try:
                    null_conn.close()
                except Exception:  # noqa: BLE001
                    pass

        # ── Test guest login ───────────────────────────────────────────────
        guest_conn: Optional[Any] = None
        if not info.null_session:
            try:
                guest_conn = SMBConnection(self.host, self.host, sess_port=self.port, timeout=10)
                guest_conn.login("guest", "", "", "", "")
                info.guest_access = True
                logger.info("SMB guest access successful on %s", self.host)
                if not info.shares:
                    self._enumerate_shares(guest_conn, info)
            except Exception:  # noqa: BLE001
                info.guest_access = False
            finally:
                if guest_conn:
                    try:
                        guest_conn.close()
                    except Exception:  # noqa: BLE001
                        pass

        # ── Perform additional enumeration with available connection ────────
        enum_conn: Optional[Any] = None
        try:
            # Use null session if available, otherwise try guest
            if info.null_session:
                enum_conn = SMBConnection(self.host, self.host, sess_port=self.port, timeout=10)
                enum_conn.login("", "", "", "", "")
            elif info.guest_access:
                enum_conn = SMBConnection(self.host, self.host, sess_port=self.port, timeout=10)
                enum_conn.login("guest", "", "", "", "")

            if enum_conn:
                # Get domain and computer info
                self._get_domain_info(enum_conn, info)

                # Enumerate users (RID cycling)
                self._enumerate_users(enum_conn, info)

                # Get password policy
                self._get_password_policy(enum_conn, info)

                # Identify printers
                self._enumerate_printers(info)

                # Recursive file search for sensitive files
                for share in info.shares:
                    if share.get("readable") and not share.get("is_default_share"):
                        try:
                            self._enumerate_files_recursive(
                                enum_conn, share.get("name"), info
                            )
                        except Exception:  # noqa: BLE001
                            pass

        except Exception as exc:  # noqa: BLE001
            logger.debug("Additional enumeration failed: %s", exc)
        finally:
            if enum_conn:
                try:
                    enum_conn.close()
                except Exception:  # noqa: BLE001
                    pass

    def _enumerate_shares(self, conn: Any, info: SMBInfo) -> None:
        """List shares and check for sensitive file patterns and access rights.

        Args:
            conn: Active SMBConnection.
            info: SMBInfo to populate in-place.
        """
        try:
            shares = conn.listShares()
        except Exception as exc:  # noqa: BLE001
            logger.debug("Failed to list shares on %s: %s", self.host, exc)
            return

        for share in shares:
            share_name = share["shi1_netname"][:-1] if share.get("shi1_netname") else "?"
            share_type = share.get("shi1_type", 0)
            share_remark = share.get("shi1_remark", "")
            if hasattr(share_remark, "__class__") and hasattr(share_remark, "decode"):
                try:
                    share_remark = share_remark.decode("utf-8", errors="replace")
                except Exception:  # noqa: BLE001
                    share_remark = str(share_remark)

            share_info: Dict[str, Any] = {
                "name": share_name,
                "type": share_type,
                "remark": share_remark,
                "files": [],
                "sensitive_files": [],
                "accessible": False,
                "readable": False,
                "writable": False,
                "is_default_share": share_name.upper() in ("IPC$", "ADMIN$", "PRINT$", "C$", "D$", "E$"),
                "is_admin_share": share_name.upper() == "ADMIN$",
            }

            # Check if it's an admin share (high-value finding)
            if share_info["is_admin_share"]:
                info.remote_admin_access = True

            # Attempt to list top-level contents
            try:
                files = conn.listPath(share_name, "*")
                share_info["accessible"] = True
                share_info["readable"] = True  # If we can list, it's readable
                top_files = []
                sensitive_files = []
                for f in files[:50]:  # Limit to 50 entries
                    fname = f.get_longname() or ""
                    top_files.append(fname)
                    if _SENSITIVE_PATTERNS.search(fname):
                        sensitive_files.append(fname)
                share_info["files"] = top_files
                share_info["sensitive_files"] = sensitive_files
            except Exception:  # noqa: BLE001
                pass

            # Test write access - try to create a hidden test file
            if share_info["readable"]:
                self._test_write_access(conn, share_name, share_info)

            info.shares.append(share_info)

    def _test_write_access(self, conn: Any, share_name: str, share_info: Dict[str, Any]) -> None:
        """Test if the share is writable by attempting to create a hidden file.

        Args:
            conn: Active SMBConnection.
            share_name: Name of the share to test.
            share_info: Share info dict to update in-place.
        """
        import tempfile
        import uuid

        test_filename = f".recon_x_test_{uuid.uuid4().hex[:8]}.tmp"

        try:
            # Try to create a test file
            file_handle = conn.createFile(
                share_name,
                test_filename,
                desiredAccess=0x0001,  # FILE_READ_DATA
                shareMode=1,  # FILE_SHARE_READ
                creationOptions=0x00000010,  # FILE_ATTRIBUTE_HIDDEN
                creationDisposition=0x02,  # FILE_CREATE
            )
            # If we got here, write is possible
            conn.closeFile(share_name, file_handle)
            # Clean up test file
            try:
                conn.deleteFile(share_name, test_filename)
            except Exception:  # noqa: BLE001
                pass
            share_info["writable"] = True
            logger.info(
                "SMB share '%s' on %s is WRITABLE", share_name, self.host
            )
        except Exception:  # noqa: BLE001
            # Expected when write is not allowed
            pass

    def _enumerate_users(self, conn: Any, info: SMBInfo) -> None:
        """Enumerate users via RID cycling on SAM.

        Args:
            conn: Active SMBConnection.
            info: SMBInfo to populate in-place.
        """
        try:
            from impacket.dcerpc.v5 import samr
            from impacket.dcerpc.v5.samr import samrQueryDomainInfo
        except ImportError:
            logger.debug("impacket.dcerpc not available for user enumeration")
            return

        try:
            # Get the remote registry binding
            rpctransport = conn.get_dce_rpc("samr")
            if not rpctransport:
                logger.debug("Could not get SAMR DCE/RPC transport")
                return

            dce = rpctransport.get_dce_rpc()
            dce.connect()

            # Connect to the SAM
            samr_handle = samr.hSamrConnect(dce)

            # Get domain handle
            domains = samr.hSamrEnumerateDomainsInSamServer(dce, samr_handle)
            if not domains:
                dce.disconnect()
                return

            # Open first domain
            domain_handle = samr.hSamrOpenDomain(dce, samr_handle, domain_rid=domains[0]["Rid"])

            # Enumerate users via RID
            users_found = []
            common_rids = list(range(1000, 1050)) + list(range(500, 530))  # Common user RIDs

            for rid in common_rids:
                try:
                    user_handle = samr.hSamrOpenUser(dce, domain_handle, user_rid=rid)
                    user_info = samr.hSamrQueryInformationUser(
                        dce, user_handle, samr.USER_INFORMATION_CLASS.UserGeneralInformation
                    )
                    username = user_info["Buffer"]["General"]["UserName"]
                    if username:
                        users_found.append({
                            "name": username,
                            "rid": rid,
                            "enabled": bool(!(user_info["Buffer"]["General"]["UserAccountControl"] & 0x0010)),
                        })
                    samr.hSamrCloseHandle(dce, user_handle)
                except Exception:  # noqa: BLE001
                    pass

            info.users = users_found
            logger.info("Enumerated %d users on %s", len(users_found), self.host)

            # Cleanup
            samr.hSamrCloseHandle(dce, domain_handle)
            samr.hSamrCloseHandle(dce, samr_handle)
            dce.disconnect()

        except Exception as exc:  # noqa: BLE001
            logger.debug("User enumeration failed on %s: %s", self.host, exc)

    def _get_domain_info(self, conn: Any, info: SMBInfo) -> None:
        """Retrieve domain information.

        Args:
            conn: Active SMBConnection.
            info: SMBInfo to populate in-place.
        """
        try:
            # Get domain from connection
            domain = conn.getServerDomain()
            info.domain = domain or ""

            # Get computer name
            computer_name = conn.getServerName()
            info.computer_name = computer_name or ""

            # Get OS and workgroup info
            os_info = conn.getServerOS()
            info.os_info = os_info or ""

            # Try to get domain info via Registry if available
            info.domain_info = {
                "domain": info.domain,
                "computer_name": info.computer_name,
                "os": info.os_info,
            }

            logger.info("Domain info: Domain=%s, Computer=%s", info.domain, info.computer_name)

        except Exception as exc:  # noqa: BLE001
            logger.debug("Domain info retrieval failed: %s", exc)

    def _get_password_policy(self, conn: Any, info: SMBInfo) -> None:
        """Retrieve password policy information via SAM.

        Args:
            conn: Active SMBConnection.
            info: SMBInfo to populate in-place.
        """
        try:
            from impacket.dcerpc.v5 import samr
        except ImportError:
            return

        try:
            rpctransport = conn.get_dce_rpc("samr")
            if not rpctransport:
                return

            dce = rpctransport.get_dce_rpc()
            dce.connect()

            samr_handle = samr.hSamrConnect(dce)
            domains = samr.hSamrEnumerateDomainsInSamServer(dce, samr_handle)

            if domains:
                domain_handle = samr.hSamrOpenDomain(dce, samr_handle, domain_rid=domains[0]["Rid"])
                policy_info = samr.hSamrQueryInformationDomain(
                    dce, domain_handle, samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation
                )

                if policy_info:
                    pwd_policy = policy_info["Buffer"]["Password"]
                    info.password_policy = {
                        "min_password_length": pwd_policy["MinPasswordLength"],
                        "password_history_length": pwd_policy["PasswordHistoryLength"],
                        "max_password_age": pwd_policy["MaxPasswordAge"],
                        "min_password_age": pwd_policy["MinPasswordAge"],
                    }
                    logger.info("Password policy retrieved: %s", info.password_policy)

                samr.hSamrCloseHandle(dce, domain_handle)

            samr.hSamrCloseHandle(dce, samr_handle)
            dce.disconnect()

        except Exception as exc:  # noqa: BLE001
            logger.debug("Password policy retrieval failed: %s", exc)

    def _enumerate_printers(self, info: SMBInfo) -> None:
        """Identify and classify printer shares.

        Args:
            info: SMBInfo to update in-place.
        """
        printers = []
        for share in info.shares:
            # PRINT$ share or share type is printer
            if share.get("name", "").upper() == "PRINT$" or share.get("type") == 3:
                printers.append({
                    "name": share.get("name"),
                    "type": share.get("type"),
                    "remark": share.get("remark"),
                    "accessible": share.get("accessible", False),
                })

        info.printers = printers
        if printers:
            logger.info("Found %d printer share(s) on %s", len(printers), self.host)

    def _enumerate_files_recursive(self, conn: Any, share_name: str, info: SMBInfo, depth: int = 0, max_depth: int = 3) -> None:
        """Recursively search shares for interesting files.

        Args:
            conn: Active SMBConnection.
            share_name: Share to enumerate.
            info: SMBInfo to populate.
            depth: Current recursion depth.
            max_depth: Maximum recursion depth to prevent excessive scanning.
        """
        if depth > max_depth:
            return

        try:
            files = conn.listPath(share_name, "*")
        except Exception:  # noqa: BLE001
            return

        for f in files:
            fname = f.get_longname() or ""
            if fname in (".", ".."):
                continue

            # Check for sensitive files
            if _SENSITIVE_PATTERNS.search(fname):
                file_path = f.get_longname() if depth == 0 else f.get_longname()
                info.files_found.append({
                    "share": share_name,
                    "path": file_path,
                    "size": f.get_file_size() if hasattr(f, "get_file_size") else 0,
                    "created": str(f.CreationTime) if hasattr(f, "CreationTime") else "",
                })

            # Recurse into directories (with depth limit)
            if f.is_directory() and depth < max_depth and fname not in (".", ".."):
                try:
                    self._enumerate_files_recursive(
                        conn, share_name, info, depth + 1, max_depth
                    )
                except Exception:  # noqa: BLE001
                    pass
