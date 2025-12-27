#!/usr/bin/env python3
"""
REVUEX Internet Brands / WebMD Recon Script
============================================

Targets with 0 known issues (best opportunities):
- accounts.webmd.com
- pets.webmd.com
- ibconnect.internetbrands.com
- exchange.pulsepoint.com (Admin Portal)
- All pulsepoint.com targets

Run: python ib_recon.py
"""

import subprocess
import sys
from datetime import datetime

BANNER = """
██████╗ ███████╗██╗   ██╗██╗   ██╗███████╗██╗  ██╗
██╔══██╗██╔════╝██║   ██║██║   ██║██╔════╝╚██╗██╔╝
██████╔╝█████╗  ██║   ██║██║   ██║█████╗   ╚███╔╝ 
██╔══██╗██╔══╝  ╚██╗ ██╔╝██║   ██║██╔══╝   ██╔██╗ 
██║  ██║███████╗ ╚████╔╝ ╚██████╔╝███████╗██╔╝ ██╗
╚═╝  ╚═╝╚══════╝  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝

    Internet Brands / WebMD Bug Bounty Recon
"""

# Priority targets (0 known issues = best opportunity)
PRIORITY_TARGETS = [
    # Auth & Accounts (HIGH VALUE)
    ("https://accounts.webmd.com", "WebMD Accounts - Auth System"),
    ("https://pets.webmd.com", "WebMD Pets - 0 known issues"),
    
    # Internal/Admin (HIGH VALUE)
    ("https://ibconnect.internetbrands.com", "IB Connect - Internal Portal"),
    ("https://exchange.pulsepoint.com", "PulsePoint Exchange - Admin"),
    
    # APIs (DIRECT TESTING)
    ("https://openapi.pulsepoint.com", "PulsePoint Open API"),
    ("https://openapitest.pulsepoint.com", "PulsePoint Test API"),
    ("https://lifeapi.pulsepoint.com", "PulsePoint Life API"),
]

# Secondary targets
SECONDARY_TARGETS = [
    ("https://www.webmd.com", "WebMD Main Site"),
    ("https://member.webmd.com", "WebMD Member Portal"),
    ("https://login.medscape.com", "Medscape Login"),
    ("https://profreg.medscape.com", "Medscape Pro Registration"),
    ("https://www.mdedge.com", "MDedge - Drupal"),
    ("https://powerpak.com", "Powerpak - ASP.NET"),
    ("https://www.globalacademycme.com", "Global Academy CME"),
    ("https://www.carsdirect.com", "CarsDirect - Java"),
    ("https://www.demandforced3.com", "Demandforce D3"),
    ("https://portalv2.lh360.com", "Lighthouse360 Portal"),
]

# PulsePoint special targets (need auth likely)
PULSEPOINT_TARGETS = [
    ("https://exchange.pulsepoint.com/AdminPortal/AdminDashBoard.aspx", "Admin Dashboard"),
    ("https://life.pulsepoint.com/Buyer/#/campaign", "Buyer Campaign"),
    ("https://signal.pulsepoint.com/hcp365/#/dashboard/advertiser/6603/overview", "HCP365 Dashboard"),
    ("https://life.pulsepoint.com/MediaPlanner/#/dashboard/targetview", "Media Planner"),
    ("https://signal.pulsepoint.com/hcpexplorer/#/dashboard/eventsExplorer", "HCP Explorer"),
    ("https://life.pulsepoint.com/EngagementAudience/#/dashboard", "Engagement Audience"),
]

def run_scan(target, name, scan_type="full"):
    """Run REVUEX scans on a target."""
    print(f"\n{'='*60}")
    print(f"TARGET: {name}")
    print(f"URL: {target}")
    print(f"{'='*60}\n")
    
    scans = []
    
    if scan_type in ["full", "tech"]:
        scans.append(("Tech Fingerprint", [
            "python", "-m", "tools.tech_fingerprinter", "-t", target, "-v"
        ]))
    
    if scan_type in ["full", "secrets"]:
        scans.append(("JS Secrets", [
            "python", "-m", "tools.js_secrets_miner", "-t", target, "-v"
        ]))
    
    if scan_type in ["full", "cors"]:
        scans.append(("CORS Scanner", [
            "python", "-m", "tools.cors", "-t", target, "-v"
        ]))
    
    if scan_type in ["full", "graphql"]:
        # Try common GraphQL endpoints
        for endpoint in ["/graphql", "/api/graphql", "/v1/graphql"]:
            scans.append((f"GraphQL ({endpoint})", [
                "python", "-m", "tools.graphql", "-t", f"{target}{endpoint}", "-v"
            ]))
    
    for scan_name, cmd in scans:
        print(f"\n[*] Running: {scan_name}")
        print(f"    Command: {' '.join(cmd)}\n")
        try:
            subprocess.run(cmd, timeout=120)
        except subprocess.TimeoutExpired:
            print(f"    [!] Timeout - skipping")
        except Exception as e:
            print(f"    [!] Error: {e}")


def main():
    print(BANNER)
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    print("=" * 60)
    print("INTERNET BRANDS / WEBMD BUG BOUNTY TARGETS")
    print("=" * 60)
    
    print("\n[PRIORITY TARGETS - 0 Known Issues]")
    for target, name in PRIORITY_TARGETS:
        print(f"  • {name}: {target}")
    
    print("\n[SECONDARY TARGETS]")
    for target, name in SECONDARY_TARGETS:
        print(f"  • {name}: {target}")
    
    print("\n" + "=" * 60)
    print("SELECT SCAN MODE:")
    print("=" * 60)
    print("1. Quick scan (Priority targets only - recommended)")
    print("2. Full scan (All targets)")
    print("3. Single target")
    print("4. API targets only")
    print("5. Exit")
    
    choice = input("\nChoice [1-5]: ").strip()
    
    if choice == "1":
        print("\n[*] Starting Priority Target Scan...")
        for target, name in PRIORITY_TARGETS:
            run_scan(target, name)
    
    elif choice == "2":
        print("\n[*] Starting Full Scan (this will take a while)...")
        for target, name in PRIORITY_TARGETS + SECONDARY_TARGETS:
            run_scan(target, name)
    
    elif choice == "3":
        print("\nAvailable targets:")
        all_targets = PRIORITY_TARGETS + SECONDARY_TARGETS
        for i, (target, name) in enumerate(all_targets, 1):
            print(f"  {i}. {name}")
        
        idx = input("\nSelect target number: ").strip()
        try:
            idx = int(idx) - 1
            if 0 <= idx < len(all_targets):
                target, name = all_targets[idx]
                run_scan(target, name)
            else:
                print("Invalid selection")
        except:
            print("Invalid input")
    
    elif choice == "4":
        print("\n[*] Starting API Target Scan...")
        api_targets = [
            ("https://openapi.pulsepoint.com", "PulsePoint Open API"),
            ("https://openapitest.pulsepoint.com", "PulsePoint Test API"),
            ("https://lifeapi.pulsepoint.com", "PulsePoint Life API"),
        ]
        for target, name in api_targets:
            run_scan(target, name)
    
    elif choice == "5":
        print("Exiting...")
        return 0
    
    else:
        print("Invalid choice")
        return 1
    
    print("\n" + "=" * 60)
    print("SCAN COMPLETE")
    print("=" * 60)
    print(f"Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("\nNext steps:")
    print("  1. Review findings above")
    print("  2. Check for JS secrets")
    print("  3. Test CORS misconfigurations")
    print("  4. Look for GraphQL introspection")
    print("  5. Create accounts for authenticated testing")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
