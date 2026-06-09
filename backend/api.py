import csv
import io
import json
import os
from datetime import datetime

from flask import Blueprint, Response, current_app, jsonify, make_response, send_file
try:
    from fpdf import FPDF
except ImportError:
    FPDF = None

try:
    from .history import HistoryManager
except ImportError:
    from history import HistoryManager

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REPORT_PATH = os.path.join(ROOT_DIR, "reports", "findings.json")
HISTORY_PATH = os.path.join(ROOT_DIR, "data", "history.json")

MODULE_LABELS = {
    "cron": "Cron",
    "systemd": "Systemd",
    "startup": "Startup",
    "ssh": "SSH",
    "ssh_config": "SSH",
}

api_bp = Blueprint("api", __name__)

history_manager = HistoryManager(HISTORY_PATH)


def _ensure_data_directory():
    os.makedirs(os.path.dirname(HISTORY_PATH), exist_ok=True)
    os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)


def _load_report() -> dict:
    _ensure_data_directory()
    if not os.path.isfile(REPORT_PATH):
        return {
            "generated_at": None,
            "total_findings": 0,
            "severity_counts": {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "findings": [],
        }

    with open(REPORT_PATH, "r", encoding="utf-8") as handle:
        raw = json.load(handle)

    findings = []
    for item in raw.get("findings", []):
        module_key = str(item.get("type", "unknown")).lower()
        module = MODULE_LABELS.get(module_key, module_key.title())
        reason = item.get("reason") or item.get("description") or "No rule description available."
        evidence = item.get("content") or item.get("evidence") or ""
        findings.append({
            "module": module,
            "severity": item.get("severity", "LOW"),
            "path": item.get("file", "unknown"),
            "description": reason,
            "evidence": evidence,
            "rule": item.get("field") or item.get("type") or "unknown",
            "detection_time": raw.get("generated_at"),
            "line": item.get("line"),
        })

    severity_counts = raw.get("severity_counts", {})
    normalized = {
        "generated_at": raw.get("generated_at"),
        "total_findings": raw.get("total_findings", len(findings)),
        "severity_counts": {
            "HIGH": severity_counts.get("HIGH", 0),
            "MEDIUM": severity_counts.get("MEDIUM", 0),
            "LOW": severity_counts.get("LOW", 0),
        },
        "findings": findings,
    }

    normalized["top_affected_files"] = _collect_top_files(findings)
    normalized["top_techniques"] = _collect_top_techniques(findings)
    normalized["module_counts"] = _collect_module_counts(findings)
    normalized["monitors"] = _build_monitor_status(findings)

    return normalized


def _collect_top_files(findings):
    counter = {}
    for item in findings:
        key = item["path"]
        counter[key] = counter.get(key, 0) + 1
    return sorted(
        [{"path": path, "count": count} for path, count in counter.items()],
        key=lambda item: item["count"],
        reverse=True,
    )[:8]


def _collect_top_techniques(findings):
    counter = {}
    for item in findings:
        key = item.get("description", "unknown")
        counter[key] = counter.get(key, 0) + 1
    return sorted(
        [{"technique": technique, "count": count} for technique, count in counter.items()],
        key=lambda item: item["count"],
        reverse=True,
    )[:8]


def _collect_module_counts(findings):
    counter = {}
    for item in findings:
        key = item.get("module", "Unknown")
        counter[key] = counter.get(key, 0) + 1
    return counter


def _build_monitor_status(findings):
    statuses = []
    for monitor in ["Cron Monitor", "Systemd Monitor", "Startup Monitor", "SSH Monitor"]:
        module_name = monitor.split()[0]
        module_findings = [item for item in findings if item.get("module") == module_name]
        count = len(module_findings)
        if count == 0:
            level = "Healthy"
            detail = "No findings detected"
        elif any(item.get("severity") == "HIGH" for item in module_findings):
            level = "Danger"
            detail = f"{count} finding(s) detected"
        else:
            level = "Warning"
            detail = f"{count} low/medium findings"

        statuses.append({
            "monitor": monitor,
            "status": level,
            "detail": detail,
        })
    return statuses


def _build_pdf(report):
    pdf = FPDF(orientation="P", unit="mm", format="A4")
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "Persistence Detection Report", ln=True)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 8, f"Generated: {report.get('generated_at', '')}", ln=True)
    pdf.cell(0, 8, f"Total findings: {report.get('total_findings', 0)}", ln=True)
    pdf.ln(4)

    for severity in ["HIGH", "MEDIUM", "LOW"]:
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, f"{severity}: {report['severity_counts'].get(severity, 0)}", ln=True)

    pdf.ln(6)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Findings", ln=True)
    pdf.set_font("Helvetica", "", 10)

    for finding in report.get("findings", []):
        pdf.multi_cell(0, 6, f"[{finding['severity']}] {finding['module']} | {finding['path']}")
        pdf.multi_cell(0, 6, f"Rule: {finding['rule']}")
        pdf.multi_cell(0, 6, f"Evidence: {finding['evidence']}")
        pdf.multi_cell(0, 6, f"Description: {finding['description']}")
        pdf.ln(2)

    return pdf


@api_bp.route("/report", methods=["GET"])
def report():
    try:
        report_data = _load_report()
        history_manager.record_scan(report_data)
        response = {
            "status": "ok",
            "report": report_data,
        }
        return jsonify(response)
    except Exception as exc:
        current_app.logger.exception("Failed to load report")
        return jsonify({"status": "error", "message": str(exc)}), 500


@api_bp.route("/history", methods=["GET"])
def history():
    try:
        return jsonify({"status": "ok", "history": history_manager.get_history()})
    except Exception as exc:
        current_app.logger.exception("Failed to load history")
        return jsonify({"status": "error", "message": str(exc)}), 500


@api_bp.route("/export/json", methods=["GET"])
def export_json():
    if not os.path.isfile(REPORT_PATH):
        return jsonify({"status": "error", "message": "Report file not available."}), 404
    return send_file(REPORT_PATH, mimetype="application/json", as_attachment=True, download_name="findings.json")


@api_bp.route("/export/csv", methods=["GET"])
def export_csv():
    report_data = _load_report()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Severity", "Module", "Path", "Description", "Evidence", "Rule", "Detection Time"])
    for finding in report_data.get("findings", []):
        writer.writerow([
            finding.get("severity"),
            finding.get("module"),
            finding.get("path"),
            finding.get("description"),
            finding.get("evidence"),
            finding.get("rule"),
            finding.get("detection_time"),
        ])

    response = make_response(output.getvalue())
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = "attachment; filename=findings.csv"
    return response


@api_bp.route("/export/pdf", methods=["GET"])
def export_pdf():
    if FPDF is None:
        return jsonify({"status": "error", "message": "Missing dependency 'fpdf2'. Install requirements.txt to enable PDF export."}), 500

    report_data = _load_report()
    pdf = _build_pdf(report_data)
    output = io.BytesIO()
    pdf.output(output)
    output.seek(0)
    return send_file(
        output,
        mimetype="application/pdf",
        as_attachment=True,
        download_name="findings.pdf",
    )
