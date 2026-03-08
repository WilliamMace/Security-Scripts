#!/usr/bin/env python3
"""
NIST 800-53 Compliance Report Generator

Generates compliance assessment reports mapped to NIST SP 800-53 Rev 5
security controls. Supports CSV and HTML output formats with control
family summaries and risk scoring.

Author: William Mace
Version: 1.0.0
Date: 2026-03-08

Usage:
    python nist_800_53_report.py --output report.csv
    python nist_800_53_report.py --output report.html --format html
    python nist_800_53_report.py --family AC --output access_control.csv
    python nist_800_53_report.py --summary
"""

import argparse
import csv
import json
import os
import sys
from datetime import datetime


# NIST 800-53 Rev 5 Control Families with sample controls
CONTROL_CATALOG = {
    "AC": {
        "name": "Access Control",
        "controls": {
            "AC-1": {"title": "Policy and Procedures", "priority": "P1", "baseline": ["LOW", "MOD", "HIGH"]},
            "AC-2": {"title": "Account Management", "priority": "P1", "baseline": ["LOW", "MOD", "HIGH"]},
            "AC-3": {"title": "Access Enforcement", "priority": "P1", "baseline": ["LOW", "MOD", "HIGH"]},
            "AC-4": {"title": "Information Flow Enforcement", "priority": "P1", "baseline": ["MOD", "HIGH"]},
            "AC-5": {"title": "Separation of Duties", "priority": "P1", "baseline": ["MOD", "HIGH"]},
            "AC-6": {"title": "Least Privilege", "priority": "P1", "baseline": ["MOD", "HIGH"]},
            "AC-7": {"title": "Unsuccessful Logon Attempts", "priority": "P1", "baseline": ["LOW", "MOD", "HIGH"]},
            "AC-8": {"title": "System Use Notification", "priority": "P1", "baseline": ["LOW", "MOD", "HIGH"]},
            "AC-11": {"title": "Device Lock", "priority": "P1", "baseline": ["MOD", "HIGH"]},
            "AC-17": {"title": "Remote Access", "priority": "P1", "baseline": ["LOW", "MOD", "HIGH"]},
        }
    },
    "AU": {
        "name": "Audit and Accountability",
        "controls": {
            "AU-1": {"title": "Policy and Procedures", "priority": "P1", "baseline": ["LOW", "MOD", "HIGH"]},
            "AU-2": {"title": "Event Logging", "priority": "P1", "baseline": ["LOW", "MOD", "HIGH"]},
            "AU-3": {"title": "Content of Audit Records", "priority": "P1", "baseline": ["LOW", "MOD", "HIGH"]},
            "AU-4": {"title": "Audit Log Storage Capacity", "priority": "P1", "baseline": ["LOW", "MOD", "HIGH"]},
            "AU-5": {"title": "Response to Audit Logging Process Failures", "priority": "P1", "baseline": ["LOW", "MOD", "HIGH"]},
            "AU-6": {"title": "Audit Record Review, Analysis, and Reporting", "priority": "P1", "baseline": ["LOW", "MOD", "HIGH"]},
            "AU-8": {"title": "Time Stamps", "priority": "P1", "baseline": ["LOW", "MOD", "HIGH"]},
            "AU-9": {"title": "Protection of Audit Information", "priority": "P1", "baseline": ["LOW", "MOD", "HIGH"]},
            "AU-11": {"title": "Audit Record Retention", "priority": "P3", "baseline": ["LOW", "MOD", "HIGH"]},
            "AU-12": {"title": "Audit Record Generation", "priority": "P1", "baseline": ["LOW", "MOD", "HIGH"]},
        }
    },
    "CM": {
        "name": "Configuration Management",
        "controls": {
            "CM-1": {"title": "Policy and Procedures", "priority": "P1", "baseline": ["LOW", "MOD", "HIGH"]},
            "CM-2": {"title": "Baseline Configuration", "priority": "P1", "baseline": ["LOW", "MOD", "HIGH"]},
            "CM-3": {"title": "Configuration Change Control", "priority": "P1", "baseline": ["MOD", "HIGH"]},
            "CM-4": {"title": "Impact Analyses", "priority": "P2", "baseline": ["LOW", "MOD", "HIGH"]},
            "CM-5": {"title": "Access Restrictions for Change", "priority": "P1", "baseline": ["MOD", "HIGH"]},
            "CM-6": {"title": "Configuration Settings", "priority": "P1", "baseline": ["LOW", "MOD", "HIGH"]},
            "CM-7": {"title": "Least Functionality", "priority": "P1", "baseline": ["LOW", "MOD", "HIGH"]},
            "CM-8": {"title": "System Component Inventory", "priority": "P1", "baseline": ["LOW", "MOD", "HIGH"]},
        }
    },
    "IA": {
        "name": "Identification and Authentication",
        "controls": {
            "IA-1": {"title": "Policy and Procedures", "priority": "P1", "baseline": ["LOW", "MOD", "HIGH"]},
            "IA-2": {"title": "Identification and Authentication (Organizational Users)", "priority": "P1", "baseline": ["LOW", "MOD", "HIGH"]},
            "IA-3": {"title": "Device Identification and Authentication", "priority": "P1", "baseline": ["MOD", "HIGH"]},
            "IA-4": {"title": "Identifier Management", "priority": "P1", "baseline": ["LOW", "MOD", "HIGH"]},
            "IA-5": {"title": "Authenticator Management", "priority": "P1", "baseline": ["LOW", "MOD", "HIGH"]},
            "IA-6": {"title": "Authentication Feedback", "priority": "P2", "baseline": ["LOW", "MOD", "HIGH"]},
            "IA-8": {"title": "Identification and Authentication (Non-Organizational Users)", "priority": "P1", "baseline": ["LOW", "MOD", "HIGH"]},
        }
    },
    "RA": {
        "name": "Risk Assessment",
        "controls": {
            "RA-1": {"title": "Policy and Procedures", "priority": "P1", "baseline": ["LOW", "MOD", "HIGH"]},
            "RA-2": {"title": "Security Categorization", "priority": "P1", "baseline": ["LOW", "MOD", "HIGH"]},
            "RA-3": {"title": "Risk Assessment", "priority": "P1", "baseline": ["LOW", "MOD", "HIGH"]},
            "RA-5": {"title": "Vulnerability Monitoring and Scanning", "priority": "P1", "baseline": ["LOW", "MOD", "HIGH"]},
            "RA-7": {"title": "Risk Response", "priority": "P1", "baseline": ["LOW", "MOD", "HIGH"]},
        }
    },
    "SC": {
        "name": "System and Communications Protection",
        "controls": {
            "SC-1": {"title": "Policy and Procedures", "priority": "P1", "baseline": ["LOW", "MOD", "HIGH"]},
            "SC-5": {"title": "Denial-of-Service Protection", "priority": "P1", "baseline": ["LOW", "MOD", "HIGH"]},
            "SC-7": {"title": "Boundary Protection", "priority": "P1", "baseline": ["LOW", "MOD", "HIGH"]},
            "SC-8": {"title": "Transmission Confidentiality and Integrity", "priority": "P1", "baseline": ["MOD", "HIGH"]},
            "SC-12": {"title": "Cryptographic Key Establishment and Management", "priority": "P1", "baseline": ["LOW", "MOD", "HIGH"]},
            "SC-13": {"title": "Cryptographic Protection", "priority": "P1", "baseline": ["LOW", "MOD", "HIGH"]},
            "SC-28": {"title": "Protection of Information at Rest", "priority": "P1", "baseline": ["MOD", "HIGH"]},
        }
    },
}


VALID_STATUSES = ["Implemented", "Partially Implemented", "Planned", "Not Implemented", "Not Applicable"]


def get_controls(family=None, baseline=None):
    """Get controls filtered by family and/or baseline level."""
    results = []
    families = {family: CONTROL_CATALOG[family]} if family and family in CONTROL_CATALOG else CONTROL_CATALOG
    
    for fam_id, fam_data in families.items():
        for ctrl_id, ctrl_info in fam_data["controls"].items():
            if baseline and baseline.upper() not in ctrl_info["baseline"]:
                continue
            results.append({
                "family_id": fam_id,
                "family_name": fam_data["name"],
                "control_id": ctrl_id,
                "title": ctrl_info["title"],
                "priority": ctrl_info["priority"],
                "baseline": ", ".join(ctrl_info["baseline"]),
                "status": "Not Assessed",
                "implementation": "",
                "risk_level": "",
                "notes": ""
            })
    
    return sorted(results, key=lambda x: x["control_id"])


def generate_csv_report(controls, output_path, system_name="System"):
    """Generate a CSV compliance report."""
    fieldnames = [
        "Control ID", "Family", "Title", "Priority", "Baseline",
        "Status", "Implementation Details", "Risk Level", "Notes"
    ]
    
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([f"NIST 800-53 Rev 5 Compliance Report - {system_name}"])
        writer.writerow([f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"])
        writer.writerow([])
        writer.writerow(fieldnames)
        
        for ctrl in controls:
            writer.writerow([
                ctrl["control_id"],
                f"{ctrl['family_id']} - {ctrl['family_name']}",
                ctrl["title"],
                ctrl["priority"],
                ctrl["baseline"],
                ctrl["status"],
                ctrl["implementation"],
                ctrl["risk_level"],
                ctrl["notes"]
            ])
    
    print(f"CSV report saved to: {output_path}")


def generate_html_report(controls, output_path, system_name="System"):
    """Generate an HTML compliance report."""
    status_colors = {
        "Implemented": "#28a745",
        "Partially Implemented": "#ffc107",
        "Planned": "#17a2b8",
        "Not Implemented": "#dc3545",
        "Not Applicable": "#6c757d",
        "Not Assessed": "#e9ecef"
    }
    
    # Calculate summary stats
    family_stats = {}
    for ctrl in controls:
        fam = ctrl["family_id"]
        if fam not in family_stats:
            family_stats[fam] = {"name": ctrl["family_name"], "total": 0, "assessed": 0, "implemented": 0}
        family_stats[fam]["total"] += 1
        if ctrl["status"] != "Not Assessed":
            family_stats[fam]["assessed"] += 1
        if ctrl["status"] == "Implemented":
            family_stats[fam]["implemented"] += 1
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>NIST 800-53 Compliance Report - {system_name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        h1 {{ color: #1a237e; }}
        h2 {{ color: #283593; border-bottom: 2px solid #283593; padding-bottom: 5px; }}
        .header {{ background: #1a237e; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
        .header h1 {{ color: white; margin: 0; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
        .summary-card {{ background: white; padding: 15px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .summary-card h3 {{ margin: 0 0 10px 0; color: #333; font-size: 14px; }}
        .summary-card .number {{ font-size: 28px; font-weight: bold; color: #1a237e; }}
        table {{ width: 100%; border-collapse: collapse; background: white; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin: 15px 0; }}
        th {{ background: #283593; color: white; padding: 10px; text-align: left; font-size: 13px; }}
        td {{ padding: 8px 10px; border-bottom: 1px solid #eee; font-size: 13px; }}
        tr:hover {{ background: #f0f0f0; }}
        .status {{ padding: 3px 8px; border-radius: 3px; color: white; font-size: 12px; font-weight: bold; }}
        .meta {{ color: #666; font-size: 13px; margin: 5px 0; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>NIST SP 800-53 Rev 5 Compliance Report</h1>
        <p class="meta">System: {system_name}</p>
        <p class="meta">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p class="meta">Total Controls: {len(controls)}</p>
    </div>
    
    <h2>Family Summary</h2>
    <div class="summary-grid">
"""
    
    for fam_id, stats in sorted(family_stats.items()):
        pct = round((stats["implemented"] / stats["total"]) * 100) if stats["total"] > 0 else 0
        html += f"""        <div class="summary-card">
            <h3>{fam_id} - {stats['name']}</h3>
            <div class="number">{pct}%</div>
            <p class="meta">{stats['implemented']}/{stats['total']} Implemented</p>
        </div>
"""
    
    html += """    </div>
    
    <h2>Control Details</h2>
    <table>
        <tr><th>Control ID</th><th>Title</th><th>Priority</th><th>Baseline</th><th>Status</th><th>Notes</th></tr>
"""
    
    for ctrl in controls:
        color = status_colors.get(ctrl["status"], "#e9ecef")
        text_color = "white" if ctrl["status"] not in ["Not Assessed"] else "#333"
        html += f"""        <tr>
            <td><strong>{ctrl['control_id']}</strong></td>
            <td>{ctrl['title']}</td>
            <td>{ctrl['priority']}</td>
            <td>{ctrl['baseline']}</td>
            <td><span class="status" style="background:{color};color:{text_color}">{ctrl['status']}</span></td>
            <td>{ctrl['notes']}</td>
        </tr>
"""
    
    html += """    </table>
</body>
</html>"""
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    
    print(f"HTML report saved to: {output_path}")


def print_summary(controls):
    """Print a compliance summary to the console."""
    print(f"\n{'=' * 65}")
    print(f"  NIST 800-53 Rev 5 Compliance Summary")
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'=' * 65}")
    
    family_stats = {}
    for ctrl in controls:
        fam = ctrl["family_id"]
        if fam not in family_stats:
            family_stats[fam] = {"name": ctrl["family_name"], "total": 0}
        family_stats[fam]["total"] += 1
    
    print(f"\n  {'Family':<8} {'Name':<45} {'Controls':>8}")
    print(f"  {'-'*8} {'-'*45} {'-'*8}")
    
    total = 0
    for fam_id, stats in sorted(family_stats.items()):
        print(f"  {fam_id:<8} {stats['name']:<45} {stats['total']:>8}")
        total += stats["total"]
    
    print(f"  {'-'*8} {'-'*45} {'-'*8}")
    print(f"  {'TOTAL':<8} {'':<45} {total:>8}")
    print(f"\n  Use --output to generate a full report (CSV or HTML).")
    print(f"{'=' * 65}\n")


def main():
    parser = argparse.ArgumentParser(
        description="NIST 800-53 Rev 5 Compliance Report Generator"
    )
    parser.add_argument("--output", "-o", help="Output file path (e.g., report.csv or report.html)")
    parser.add_argument("--format", "-f", choices=["csv", "html"], default="csv", help="Output format (default: csv)")
    parser.add_argument("--family", help="Filter by control family (e.g., AC, AU, CM)")
    parser.add_argument("--baseline", "-b", choices=["LOW", "MOD", "HIGH"], help="Filter by baseline level")
    parser.add_argument("--system", "-s", default="Information System", help="System name for the report")
    parser.add_argument("--summary", action="store_true", help="Print control family summary")
    parser.add_argument("--json", "-j", action="store_true", help="Output as JSON")
    
    args = parser.parse_args()
    
    print(f"\n[*] NIST 800-53 Rev 5 Compliance Report Generator v1.0.0")
    
    if args.family and args.family.upper() not in CONTROL_CATALOG:
        print(f"Error: Unknown family '{args.family}'. Valid: {', '.join(CONTROL_CATALOG.keys())}")
        sys.exit(1)
    
    family = args.family.upper() if args.family else None
    controls = get_controls(family=family, baseline=args.baseline)
    
    if args.summary:
        print_summary(controls)
        return
    
    if args.json:
        print(json.dumps(controls, indent=2))
        return
    
    if not args.output:
        print_summary(controls)
        print("  Tip: Use --output report.csv or --output report.html to generate a file.\n")
        return
    
    fmt = args.format
    if args.output.endswith(".html"):
        fmt = "html"
    elif args.output.endswith(".csv"):
        fmt = "csv"
    
    if fmt == "html":
        generate_html_report(controls, args.output, args.system)
    else:
        generate_csv_report(controls, args.output, args.system)
    
    print(f"[*] Report includes {len(controls)} controls across {len(set(c['family_id'] for c in controls))} families.")
    print(f"[*] Done.\n")


if __name__ == "__main__":
    main()
