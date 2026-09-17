"""
updater.py — Shared auto-update module for ThreatScanner (GUI + CLI).

Checks the configured GitHub repository for the latest release.
If a newer version is found, the new installer is downloaded and run
silently, then the current process exits to allow the installation.

Usage:
    from updater import check_for_updates
    check_for_updates(current_version="1.0.0")

GitHub repo is set via GITHUB_REPO constant below.
Replace with your actual <owner>/<repo> before building.
"""

import os
import sys
import subprocess
import tempfile
import urllib.request
import urllib.error
import json

# ─── CONFIG ──────────────────────────────────────────────────────────────────
GITHUB_REPO   = "kuna9457/Threat_Releases"           # TODO: replace with e.g. "kunal/ThreatScanner"
ASSET_NAME    = "ThreatScanner_Setup.exe"
API_URL       = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
REQUEST_TIMEOUT = 10   # seconds
# ─────────────────────────────────────────────────────────────────────────────


def _parse_version(tag: str) -> tuple:
    """Convert a version tag like 'v1.2.3' or '1.2.3' to a comparable tuple."""
    return tuple(int(x) for x in tag.lstrip("v").split(".") if x.isdigit())


def check_for_updates(current_version: str, silent: bool = False, log_callback=None) -> bool:
    """
    Check GitHub for a newer release.

    Args:
        current_version: The currently running version string (e.g. "1.0.0").
        silent: If True, suppress print output.
        log_callback: Optional callable(str) used by GUI to redirect log output.

    Returns:
        True if an update was triggered (process will exit shortly),
        False if already up-to-date or if the check failed.
    """
    def _log(msg: str):
        if log_callback:
            log_callback(msg)
        elif not silent:
            print(msg)

    _log(f"[*] Checking for updates (current version: {current_version})...")

    try:
        req = urllib.request.Request(
            API_URL,
            headers={"User-Agent": "ThreatScanner-Updater/1.0"},
        )
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, Exception) as exc:
        _log(f"[!] Update check failed (network issue): {exc}")
        return False

    latest_tag = data.get("tag_name", "")
    if not latest_tag:
        _log("[!] Could not determine latest version. Skipping update.")
        return False

    try:
        latest  = _parse_version(latest_tag)
        current = _parse_version(current_version)
    except (ValueError, TypeError):
        _log("[!] Version format error. Skipping update.")
        return False

    if latest <= current:
        _log(f"[+] Already up to date ({current_version}).")
        return False

    _log(f"[!] Update available! Latest: {latest_tag}  |  Installed: v{current_version}")
    _log("[*] Downloading update — this may take a moment...")

    # Find the installer asset in the release
    assets    = data.get("assets", [])
    asset_url = None
    for asset in assets:
        if asset.get("name", "").lower() == ASSET_NAME.lower():
            asset_url = asset.get("browser_download_url")
            break

    if not asset_url:
        _log(f"[!] Installer asset '{ASSET_NAME}' not found in release. Skipping update.")
        return False

    # Download installer to temp directory
    tmp_dir        = tempfile.gettempdir()
    installer_path = os.path.join(tmp_dir, ASSET_NAME)

    try:
        urllib.request.urlretrieve(asset_url, installer_path)
    except Exception as exc:
        _log(f"[!] Download failed: {exc}")
        return False

    _log("[+] Download complete. Launching installer silently...")
    _log("[*] The application will now close and update itself. Please wait...")

    # Launch the installer silently in the background and exit
    try:
        subprocess.Popen(
            [installer_path, "/VERYSILENT", "/SP-", "/NORESTART"],
            close_fds=True,
            creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
        )
    except Exception as exc:
        _log(f"[!] Could not launch installer: {exc}")
        return False

    import time
    time.sleep(1)
    sys.exit(0)
