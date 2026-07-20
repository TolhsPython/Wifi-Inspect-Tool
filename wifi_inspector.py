#!/usr/bin/env python3
"""
wifi_inspector.py

Windows-only utility that:
  - Lists saved Wi-Fi profiles and (where available) their passwords.
  - Scans all currently available Wi-Fi networks (SSIDs, signal, security, BSSIDs).
  - Shows which available SSIDs correspond to saved profiles and prints stored passwords.

Usage:
  python wifi_inspector.py            # prints results to console
  python wifi_inspector.py --csv out.csv  # also save results to CSV
"""

import subprocess
import argparse
import csv
import sys


def run_cmd(cmd):
    """Run a shell command and return decoded output (str)."""
    try:
        output = subprocess.check_output(cmd, shell=True)
        return output.decode(errors="ignore", encoding="utf-8")
    except subprocess.CalledProcessError as e:
        return e.output.decode(errors="ignore") if e.output else ""


def get_saved_profiles():
    """Return a list of saved Wi-Fi profile names on this machine."""
    out = run_cmd('netsh wlan show profiles')
    profiles = []
    for line in out.splitlines():
        line = line.strip()
        if line.lower().startswith("all user profile") or line.lower().startswith("user profile"):
            parts = line.split(":", 1)
            if len(parts) == 2:
                name = parts[1].strip().strip('"')
                if name:
                    profiles.append(name)
    return profiles


def get_profile_password(profile):
    """Return the password for a saved profile, or None if not present."""
    safe = profile.replace('"', '\\"')
    out = run_cmd(f'netsh wlan show profile name="{safe}" key=clear')
    for line in out.splitlines():
        line = line.strip()
        if line.lower().startswith("key content"):
            parts = line.split(":", 1)
            if len(parts) == 2:
                return parts[1].strip()
    return None


def scan_available_networks():
    """Scan nearby Wi-Fi networks and return a list of dicts with details."""
    out = run_cmd('netsh wlan show networks mode=bssid')
    networks = []
    current = None

    for raw in out.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            continue

        if stripped.lower().startswith("ssid ") and ":" in stripped:
            parts = stripped.split(":", 1)
            ssid_name = parts[1].strip().strip('"')
            if current:
                networks.append(current)
            current = {
                "ssid": ssid_name,
                "network_type": None,
                "authentication": None,
                "encryption": None,
                "bssids": []
            }
            continue

        if current is None:
            continue

        if stripped.lower().startswith("network type"):
            current["network_type"] = stripped.split(":", 1)[1].strip()
        elif stripped.lower().startswith("authentication"):
            current["authentication"] = stripped.split(":", 1)[1].strip()
        elif stripped.lower().startswith("encryption"):
            current["encryption"] = stripped.split(":", 1)[1].strip()
        elif stripped.lower().startswith("bssid"):
            parts = stripped.split(":", 1)
            bssid = parts[1].strip()
            current["bssids"].append(
                {"bssid": bssid, "signal": None, "radio_type": None})
        elif stripped.lower().startswith("signal"):
            parts = stripped.split(":", 1)
            signal = parts[1].strip()
            if current["bssids"]:
                current["bssids"][-1]["signal"] = signal
        elif stripped.lower().startswith("radio type"):
            parts = stripped.split(":", 1)
            val = parts[1].strip()
            if current["bssids"]:
                current["bssids"][-1]["radio_type"] = val

    if current:
        networks.append(current)

    return networks


def combine_and_print(profiles, networks, csv_path=None):
    """Combine info, print to console, optionally write CSV."""
    profile_set = {p.lower(): p for p in profiles}
    profile_password_cache = {}

    rows = []
    print("\n=== Saved Wi-Fi Profiles (on this PC) ===")
    if not profiles:
        print("  (none found)")
    for p in profiles:
        pw = get_profile_password(p)
        profile_password_cache[p.lower()] = pw
        pw_display = pw if pw else "(no password stored / open network)"
        print(f"  • {p}  → {pw_display}")

    print("\n=== Available Wi-Fi Networks (scan) ===")
    if not networks:
        print("  (no networks found or scan failed)")
    for net in networks:
        ssid = net["ssid"]
        auth = net.get("authentication") or ""
        enc = net.get("encryption") or ""
        known = profile_set.get(ssid.lower())
        saved_pw = profile_password_cache.get(ssid.lower())
        known_str = "Yes" if known else "No"
        pw_display = saved_pw if saved_pw else "(none)"
        print(f"\nSSID: {ssid}")
        print(f"  Known (saved profile): {known_str}")
        if known:
            print(f"  Saved profile name: {known}")
            print(f"  Stored password: {pw_display}")
        print(f"  Authentication: {auth} | Encryption: {enc}")
        if net["bssids"]:
            print("  BSSIDs:")
            for b in net["bssids"]:
                bssid = b.get("bssid") or ""
                signal = b.get("signal") or ""
                radio = b.get("radio_type") or ""
                print(f"    - {bssid}  | Signal: {signal}  | Radio: {radio}")

        # Prepare CSV row(s)
        if net["bssids"]:
            for b in net["bssids"]:
                rows.append({
                    "ssid": ssid,
                    "known_profile": known or "",
                    "stored_password": saved_pw or "",
                    "authentication": auth,
                    "encryption": enc,
                    "bssid": b.get("bssid") or "",
                    "signal": b.get("signal") or "",
                    "radio": b.get("radio_type") or ""
                })
        else:
            rows.append({
                "ssid": ssid,
                "known_profile": known or "",
                "stored_password": saved_pw or "",
                "authentication": auth,
                "encryption": enc,
                "bssid": "",
                "signal": "",
                "radio": ""
            })

    # Optionally write CSV
    if csv_path:
        fieldnames = [
            "ssid",
            "known_profile",
            "stored_password",
            "authentication",
            "encryption",
            "bssid",
            "signal",
            "radio"
        ]
        try:
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for r in rows:
                    writer.writerow(r)
            print(f"\n✅ Results written to CSV: {csv_path}")
        except Exception as e:
            print(f"\n❌ Failed to write CSV: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Wi-Fi inspector: saved profiles + available networks (Windows only)")
    parser.add_argument("--csv", "-c", metavar="FILE",
                        help="Save results to CSV file")
    args = parser.parse_args()

    if sys.platform.lower().startswith("win"):
        print("Scanning saved profiles and available Wi-Fi networks (Windows)...")
    else:
        print("This script is Windows-only (uses netsh). Exiting.")
        sys.exit(1)

    profiles = get_saved_profiles()
    networks = scan_available_networks()
    combine_and_print(profiles, networks, csv_path=args.csv)


if __name__ == "__main__":
    main()
