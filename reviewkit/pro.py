"""Pro license validation for reviewkit."""

import os
import hashlib
import json
import time
from pathlib import Path


LICENSE_FILE = Path.home() / ".reviewkit" / "license.json"
API_URL = "https://api.reviewkit.dev"  # Future: license server


def is_pro():
    """Check if a valid Pro license exists."""
    if os.environ.get("REVIEWKIT_PRO_KEY"):
        return _validate_key(os.environ["REVIEWKIT_PRO_KEY"])
    if LICENSE_FILE.exists():
        try:
            data = json.loads(LICENSE_FILE.read_text())
            return _validate_key(data.get("key", ""))
        except (json.JSONDecodeError, OSError):
            return False
    return False


def activate(key):
    """Activate a Pro license key."""
    if _validate_key(key):
        LICENSE_FILE.parent.mkdir(parents=True, exist_ok=True)
        LICENSE_FILE.write_text(json.dumps({"key": key, "activated": time.time()}))
        return True
    return False


def _validate_key(key):
    """Validate a license key format.

    Keys follow the format: RK-XXXX-XXXX-XXXX-XXXX
    Local validation only (offline-friendly).
    """
    if not key:
        return False
    # Basic format check
    parts = key.split("-")
    if len(parts) == 5 and parts[0] == "RK" and all(len(p) == 4 for p in parts[1:]):
        return True
    return False


def require_pro(feature_name="this feature"):
    """Decorator/wrapper to gate Pro features."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            if not is_pro():
                print(f"\n  '{feature_name}' requires reviewkit Pro.")
                print(f"  Get your license at: https://gumroad.com/l/reviewkit")
                print(f"  Or set REVIEWKIT_PRO_KEY environment variable.\n")
                raise SystemExit(1)
            return func(*args, **kwargs)
        return wrapper
    return decorator
