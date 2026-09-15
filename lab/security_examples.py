from __future__ import annotations
import hmac
import ipaddress
import re
from pathlib import Path
from urllib.parse import urlsplit

class UnsafeInput(ValueError):
    pass

def vulnerable_path(root: Path, supplied: str) -> Path:
    """LAB ONLY: joins input without containment validation."""
    return root / supplied

def safe_path(root: Path, supplied: str) -> Path:
    candidate = (root / supplied).resolve()
    base = root.resolve()
    if not candidate.is_relative_to(base):
        raise UnsafeInput("path escapes configured root")
    return candidate

def vulnerable_zip_target(root: Path, member: str) -> Path:
    """LAB ONLY: trusts an archive member name."""
    return root / member

def safe_zip_target(root: Path, member: str) -> Path:
    if member.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", member):
        raise UnsafeInput("absolute archive member")
    return safe_path(root, member.replace("\\", "/"))

def vulnerable_command(tool: str, user_value: str) -> str:
    """LAB ONLY: creates a string suitable for unsafe shell execution."""
    return f"{tool} --input {user_value}"

def safe_command(tool: str, user_value: str) -> list[str]:
    return [tool, "--input", user_value]

def vulnerable_url_allowed(url: str) -> bool:
    """LAB ONLY: validates only the scheme."""
    return urlsplit(url).scheme in {"http", "https"}

def safe_url_allowed(url: str, resolved_ips: list[str]) -> bool:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        return False
    if parsed.port not in (None, 443):
        return False
    try:
        addresses = [ipaddress.ip_address(value) for value in resolved_ips]
    except ValueError:
        return False
    return bool(addresses) and all(a.is_global for a in addresses)

def vulnerable_token_equal(expected: bytes, supplied: bytes) -> bool:
    """LAB ONLY: ordinary equality may reveal early mismatch timing."""
    return expected == supplied

def safe_token_equal(expected: bytes, supplied: bytes) -> bool:
    return hmac.compare_digest(expected, supplied)

PNG = b"\x89PNG\r\n\x1a\n"
JPEG = b"\xff\xd8\xff"

def vulnerable_upload_allowed(filename: str, data: bytes) -> bool:
    """LAB ONLY: trusts a filename extension."""
    return Path(filename).suffix.lower() in {".png", ".jpg", ".jpeg"}

def safe_upload_allowed(filename: str, data: bytes, max_bytes: int = 2_000_000) -> bool:
    name = Path(filename).name
    if name != filename or len(data) == 0 or len(data) > max_bytes:
        return False
    suffix = Path(name).suffix.lower()
    return (suffix == ".png" and data.startswith(PNG)) or (suffix in {".jpg", ".jpeg"} and data.startswith(JPEG))
