import json
import os
import html
import datetime
from colorama import Fore, Style, init
from modules import cron_detector, systemd_detector, startup_detector, ssh_detector

init(autoreset=True)

REPORT_PATH = "reports/findings.json"
DASHBOARD_PATH = "reports/dashboard.html"

SEVERITY_COLORS = {
    "HIGH":   Fore.RED + Style.BRIGHT,
    "MEDIUM": Fore.YELLOW + Style.BRIGHT,
    "LOW":    Fore.CYAN,
}

MODULES = [
    ("scanning cron jobs",            cron_detector),
    ("scanning systemd services",     systemd_detector),
    ("scanning startup scripts",      startup_detector),
    ("scanning ssh authorized keys",  ssh_detector),
]


def color(severity):
    return SEVERITY_COLORS.get(severity, Fore.WHITE)


def print_finding(f):
    sev = f.get("severity", "?")
    c = color(sev)
    label = f"[{sev}]"
    location = f['file']
    if "line" in f:
        location += f" (line {f['line']})"
    if "field" in f:
        location += f" [{f['field']}]"

    print(f"\n  {c}{label}{Style.RESET_ALL} {f['type'].upper()} — {location}")
    if "content" in f:
        print(f"  {Fore.WHITE}  {f['content'][:100]}{Style.RESET_ALL}")
    print(f"    reason: {f['reason']}")


def print_findings(findings):
    if not findings:
        print(f"  {Fore.GREEN}[ok]{Style.RESET_ALL} no suspicious entries found")
        return
    for f in findings:
        print_finding(f)


def print_summary(all_findings):
    high   = sum(1 for f in all_findings if f.get("severity") == "HIGH")
    medium = sum(1 for f in all_findings if f.get("severity") == "MEDIUM")
    low    = sum(1 for f in all_findings if f.get("severity") == "LOW")
    total  = len(all_findings)

    print("\n" + "=" * 50)
    print("  summary")
    print("=" * 50)

    if total == 0:
        print(f"  {Fore.GREEN}no findings — system looks clean{Style.RESET_ALL}")
        return

    if high > 0:
        print(f"  {color('HIGH')}HIGH   : {high}{Style.RESET_ALL}")
    if medium > 0:
        print(f"  {color('MEDIUM')}MEDIUM : {medium}{Style.RESET_ALL}")
    if low > 0:
        print(f"  {color('LOW')}LOW    : {low}{Style.RESET_ALL}")

    print(f"  total  : {total}")


def save_report(findings):
    os.makedirs("reports", exist_ok=True)

    report = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "total_findings": len(findings),
        "severity_counts": {
            "HIGH":   sum(1 for f in findings if f.get("severity") == "HIGH"),
            "MEDIUM": sum(1 for f in findings if f.get("severity") == "MEDIUM"),
            "LOW":    sum(1 for f in findings if f.get("severity") == "LOW"),
        },
        "findings": findings,
    }

    with open(REPORT_PATH, "w") as out:
        json.dump(report, out, indent=4)

    print(f"\n  report saved → {REPORT_PATH}")
    save_dashboard(findings)


def save_dashboard(findings):
    summary = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "total_findings": len(findings),
        "severity_counts": {
            "HIGH":   sum(1 for f in findings if f.get("severity") == "HIGH"),
            "MEDIUM": sum(1 for f in findings if f.get("severity") == "MEDIUM"),
            "LOW":    sum(1 for f in findings if f.get("severity") == "LOW"),
        },
        "type_counts": {
            t: sum(1 for f in findings if f.get("type") == t)
            for t in sorted({f.get("type") for f in findings})
        }
    }
    rows = "\n".join(_generate_row(f) for f in findings)
    types_html = "\n".join(
        f"<li><strong>{html.escape(str(t))}</strong>: {c}</li>"
        for t, c in summary["type_counts"].items()
    )
    total = summary["total_findings"] or 1
    page = """<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <title>Persistence Detection Dashboard</title>
  <style>
    body { font-family: Arial, sans-serif; color: #222; margin: 0; padding: 0; background: #f6f7fb; }
    .container { max-width: 1080px; margin: 0 auto; padding: 24px; }
    h1 { margin-bottom: 0.1rem; }
    .meta { color: #555; margin-bottom: 24px; }
    .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 24px; }
    .card { background: #fff; border-radius: 14px; padding: 18px; box-shadow: 0 10px 25px rgba(15, 23, 42, 0.08); }
    .card h2 { margin: 0 0 8px; font-size: 1.1rem; }
    .card .value { font-size: 2.2rem; font-weight: 700; }
    .bar { height: 12px; background: #ddd; border-radius: 6px; margin-top: 10px; overflow: hidden; }
    .bar span { display: block; height: 100%; border-radius: 6px; }
    .high { background: #d9534f; }
    .medium { background: #f0ad4e; }
    .low { background: #5bc0de; }
    .filters { display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 16px; align-items: center; }
    .filters input { flex: 1; padding: 10px 12px; border: 1px solid #ccc; border-radius: 8px; }
    .table-wrapper { overflow-x: auto; background: #fff; border-radius: 14px; box-shadow: 0 10px 25px rgba(15, 23, 42, 0.08); }
    table { width: 100%; border-collapse: collapse; min-width: 860px; }
    th, td { text-align: left; padding: 14px 12px; border-bottom: 1px solid #eceeef; }
    th { background: #f3f5f9; position: sticky; top: 0; z-index: 1; }
    tr:hover { background: #f9fbff; }
    .severity-high { color: #c12f2f; font-weight: 700; }
    .severity-medium { color: #b35f0e; font-weight: 700; }
    .severity-low { color: #1384a8; font-weight: 700; }
    .empty { color: #666; padding: 24px; }
  </style>
</head>
<body>
  <div class=\"container\">
    <h1>Persistence Detection Dashboard</h1>
    <div class=\"meta\">Report generated at <<<GENERATED_AT>>> UTC · Total findings: <<<TOTAL_FINDINGS>>></div>
    <div class=\"cards\">
      <div class=\"card\">
        <h2>High</h2>
        <div class=\"value\"><<<HIGH_COUNT>>></div>
        <div class=\"bar\"><span class=\"high\" style=\"width: <<<HIGH_BAR>>>%\"></span></div>
      </div>
      <div class=\"card\">
        <h2>Medium</h2>
        <div class=\"value\"><<<MEDIUM_COUNT>>></div>
        <div class=\"bar\"><span class=\"medium\" style=\"width: <<<MEDIUM_BAR>>>%\"></span></div>
      </div>
      <div class=\"card\">
        <h2>Low</h2>
        <div class=\"value\"><<<LOW_COUNT>>></div>
        <div class=\"bar\"><span class=\"low\" style=\"width: <<<LOW_BAR>>>%\"></span></div>
      </div>
    </div>
    <div class=\"card\">
      <h2>Findings by type</h2>
      <ul>
        <<<TYPE_LIST>>>
      </ul>
    </div>
    <div class=\"filters\">
      <input id=\"search\" placeholder=\"Filter findings by file, type, reason, or content...\" oninput=\"filterTable()\">
    </div>
    <div class=\"table-wrapper\">
      <table id=\"findingsTable\">
        <thead>
          <tr>
            <th>Severity</th>
            <th>Type</th>
            <th>File</th>
            <th>Field</th>
            <th>Line</th>
            <th>Reason</th>
            <th>Content</th>
          </tr>
        </thead>
        <tbody>
          <<<FINDINGS_ROWS>>>
        </tbody>
      </table>
    </div>
  </div>
  <script>
    function filterTable() {
      const filter = document.getElementById('search').value.toLowerCase();
      const rows = document.querySelectorAll('#findingsTable tbody tr');
      rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        row.style.display = text.includes(filter) ? '' : 'none';
      });
    }
  </script>
</body>
</html>"""
    page = page.replace('<<<GENERATED_AT>>>', html.escape(summary['generated_at']))
    page = page.replace('<<<TOTAL_FINDINGS>>>', str(summary['total_findings']))
    page = page.replace('<<<HIGH_COUNT>>>', str(summary['severity_counts']['HIGH']))
    page = page.replace('<<<MEDIUM_COUNT>>>', str(summary['severity_counts']['MEDIUM']))
    page = page.replace('<<<LOW_COUNT>>>', str(summary['severity_counts']['LOW']))
    page = page.replace('<<<HIGH_BAR>>>', str(summary['severity_counts']['HIGH'] * 100 / total))
    page = page.replace('<<<MEDIUM_BAR>>>', str(summary['severity_counts']['MEDIUM'] * 100 / total))
    page = page.replace('<<<LOW_BAR>>>', str(summary['severity_counts']['LOW'] * 100 / total))
    page = page.replace('<<<TYPE_LIST>>>', types_html)
    page = page.replace('<<<FINDINGS_ROWS>>>', rows)
    with open(DASHBOARD_PATH, 'w') as out:
        out.write(page)

    print(f"  dashboard saved → {DASHBOARD_PATH}")


def _html_escape(value):
    return html.escape(str(value or ""), quote=True)


def _generate_row(f):
    severity = f.get("severity", "?")
    css_class = f"severity-{severity.lower()}"
    return (
        "<tr>"
        f"<td class=\"{css_class}\">{_html_escape(severity)}</td>"
        f"<td>{_html_escape(f.get('type', ''))}</td>"
        f"<td>{_html_escape(f.get('file', ''))}</td>"
        f"<td>{_html_escape(f.get('field', ''))}</td>"
        f"<td>{_html_escape(f.get('line', ''))}</td>"
        f"<td>{_html_escape(f.get('reason', ''))}</td>"
        f"<td>{_html_escape(f.get('content', ''))}</td>"
        "</tr>"
    )


def main():
    print(Style.BRIGHT + "=" * 50)
    print("  linux persistence detector")
    print("=" * 50 + Style.RESET_ALL)

    all_findings = []

    for label, module in MODULES:
        print(f"\n{Fore.BLUE}[*]{Style.RESET_ALL} {label}...")
        findings = module.run()
        all_findings.extend(findings)
        print_findings(findings)

    print_summary(all_findings)
    save_report(all_findings)


if __name__ == "__main__":
    main()