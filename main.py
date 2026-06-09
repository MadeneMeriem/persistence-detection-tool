import json
import os
from modules import cron_detector

REPORT_PATH = "reports/findings.json"


def print_findings(findings):
    if not findings:
        print("[ok] no suspicious entries found")
        return
    for f in findings:
        sev = f.get("severity", "?")
        print(f"\n[{sev}] {f['type'].upper()} — {f['file']} (line {f.get('line', '?')})")
        print(f"    {f['content']}")
        print(f"    reason: {f['reason']}")


def save_report(findings):
    os.makedirs("reports", exist_ok=True)
    with open(REPORT_PATH, "w") as out:
        json.dump(findings, out, indent=4)
    print(f"\n[*] report saved to {REPORT_PATH}")


def main():
    print("=" * 50)
    print("  linux persistence detector")
    print("=" * 50)

    all_findings = []

    print("\n[*] scanning cron jobs...")
    cron_findings = cron_detector.run()
    all_findings.extend(cron_findings)
    print_findings(cron_findings)

    save_report(all_findings)


if __name__ == "__main__":
    main()