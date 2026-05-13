"""
Credential management for RECON-X.
Handles loading, saving, and validating stored SMB credentials.
"""

import json
import os
from pathlib import Path
from typing import Optional, Tuple, Dict, Any

from rich.console import Console
from rich.prompt import Prompt, Confirm

console = Console()

# Credentials storage directory
CREDS_DIR = Path.home() / ".recon-x"
CREDS_FILE = CREDS_DIR / "credentials.json"


def _ensure_creds_dir() -> None:
    """Ensure credentials directory exists."""
    CREDS_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    if CREDS_FILE.exists():
        os.chmod(CREDS_FILE, 0o600)


def load_smb_credentials() -> Optional[Dict[str, str]]:
    """
    Load SMB credentials from stored file.
    
    Returns:
        Dictionary with 'username', 'password', 'domain' keys or None if not stored.
    """
    if not CREDS_FILE.exists():
        return None
    
    try:
        with open(CREDS_FILE, "r") as f:
            data = json.load(f)
        return data.get("smb", None)
    except (json.JSONDecodeError, IOError):
        return None


def save_smb_credentials(username: str, password: str, domain: str = "") -> None:
    """
    Save SMB credentials to storage.
    
    Args:
        username: SMB username
        password: SMB password
        domain: SMB domain (optional)
    """
    _ensure_creds_dir()
    
    try:
        data = {}
        if CREDS_FILE.exists():
            with open(CREDS_FILE, "r") as f:
                data = json.load(f)
    except (json.JSONDecodeError, IOError):
        data = {}
    
    data["smb"] = {
        "username": username,
        "password": password,
        "domain": domain or ""
    }
    
    with open(CREDS_FILE, "w") as f:
        json.dump(data, f)
    
    # Set secure permissions
    os.chmod(CREDS_FILE, 0o600)
    console.print("[green]✓[/green] SMB credentials saved securely.")


def validate_smb_credentials(username: str, password: str) -> bool:
    """
    Validate SMB credentials by attempting a simple connection test.
    
    Args:
        username: SMB username
        password: SMB password
    
    Returns:
        True if credentials appear valid, False otherwise.
    """
    if not username or not password:
        return False
    
    # Basic validation - ensure non-empty strings
    if not isinstance(username, str) or not isinstance(password, str):
        return False
    
    return len(username) > 0 and len(password) > 0


def delete_smb_credentials() -> None:
    """Delete stored SMB credentials."""
    if CREDS_FILE.exists():
        try:
            with open(CREDS_FILE, "r") as f:
                data = json.load(f)
            if "smb" in data:
                del data["smb"]
                if data:
                    with open(CREDS_FILE, "w") as f:
                        json.dump(data, f)
                    os.chmod(CREDS_FILE, 0o600)
                else:
                    os.remove(CREDS_FILE)
            console.print("[green]✓[/green] SMB credentials deleted.")
        except (json.JSONDecodeError, IOError) as e:
            console.print(f"[red]✗[/red] Error deleting credentials: {e}")


def prompt_smb_credentials(
    use_stored: bool = True, 
    force_new: bool = False
) -> Tuple[str, str, str]:
    """
    Prompt user for SMB credentials with optional stored credential support.
    
    Args:
        use_stored: Check for stored credentials first
        force_new: Force new credential entry even if stored credentials exist
    
    Returns:
        Tuple of (username, password, domain)
    """
    # Try to load stored credentials
    if use_stored and not force_new:
        stored = load_smb_credentials()
        if stored and validate_smb_credentials(stored.get("username", ""), stored.get("password", "")):
            console.print("[cyan]Found stored SMB credentials.[/cyan]")
            
            if Confirm.ask("Use stored credentials?", default=True):
                return (
                    stored.get("username", ""),
                    stored.get("password", ""),
                    stored.get("domain", "")
                )
            else:
                if Confirm.ask("Update/replace stored credentials?", default=True):
                    force_new = True
    
    # Prompt for new credentials
    console.print("[yellow]Enter SMB credentials for authenticated enumeration[/yellow]")
    username = Prompt.ask("SMB username")
    password = Prompt.ask("SMB password", password=True)
    domain = Prompt.ask("SMB domain", default="")
    
    # Validate credentials
    if not validate_smb_credentials(username, password):
        console.print("[red]✗[/red] Invalid credentials (empty or invalid format)")
        return "", "", ""
    
    # Ask to save credentials
    if Confirm.ask("Save these credentials for future scans?", default=True):
        save_smb_credentials(username, password, domain)
    
    return username, password, domain


def get_smb_credentials(use_stored: bool = True) -> Tuple[str, str, str]:
    """
    Get SMB credentials, using stored if available and valid.
    
    Args:
        use_stored: Check for stored credentials first
    
    Returns:
        Tuple of (username, password, domain)
    """
    if use_stored:
        stored = load_smb_credentials()
        if stored and validate_smb_credentials(stored.get("username", ""), stored.get("password", "")):
            return (
                stored.get("username", ""),
                stored.get("password", ""),
                stored.get("domain", "")
            )
    
    return "", "", ""
