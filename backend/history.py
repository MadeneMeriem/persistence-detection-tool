import json
import os
from datetime import datetime


class HistoryManager:
    def __init__(self, path):
        self.path = path
        self.history = {"updated_at": None, "scans": []}
        self._load()

    def _load(self):
        if not os.path.isfile(self.path):
            return
        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                self.history = json.load(handle)
        except (json.JSONDecodeError, PermissionError):
            self.history = {"updated_at": None, "scans": []}

    def _save(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump(self.history, handle, indent=2)

    @staticmethod
    def _fingerprint(finding):
        return "|".join(
            str(finding.get(key, "")).strip().lower()
            for key in ["module", "path", "rule", "description", "evidence"]
        )

    @staticmethod
    def _summary_for_finding(finding):
        return {
            "module": finding.get("module"),
            "path": finding.get("path"),
            "severity": finding.get("severity"),
            "rule": finding.get("rule"),
            "description": finding.get("description"),
            "evidence": finding.get("evidence"),
        }

    def _compare(self, previous, current):
        prev_map = {self._fingerprint(item): item for item in previous}
        curr_map = {self._fingerprint(item): item for item in current}

        new_findings = [item for key, item in curr_map.items() if key not in prev_map]
        removed_findings = [item for key, item in prev_map.items() if key not in curr_map]
        severity_changes = []

        for key, current_item in curr_map.items():
            previous_item = prev_map.get(key)
            if previous_item and previous_item.get("severity") != current_item.get("severity"):
                severity_changes.append({
                    "module": current_item.get("module"),
                    "path": current_item.get("path"),
                    "from": previous_item.get("severity"),
                    "to": current_item.get("severity"),
                })

        return {
            "new_findings": new_findings,
            "removed_findings": removed_findings,
            "severity_changes": severity_changes,
        }

    def record_scan(self, report):
        generated_at = report.get("generated_at")
        if not generated_at:
            return

        scans = self.history.get("scans", [])
        if scans and scans[-1].get("generated_at") == generated_at:
            return

        previous_findings = scans[-1].get("findings", []) if scans else []
        current_findings = [self._summary_for_finding(item) for item in report.get("findings", [])]
        comparison = self._compare(previous_findings, current_findings)

        scan_summary = {
            "generated_at": generated_at,
            "total_findings": report.get("total_findings", len(current_findings)),
            "severity_counts": report.get("severity_counts", {}),
            "module_counts": report.get("module_counts", {}),
            "new_findings": len(comparison["new_findings"]),
            "removed_findings": len(comparison["removed_findings"]),
            "severity_changes": comparison["severity_changes"],
            "new_modules": sorted({item.get("module") for item in comparison["new_findings"]}),
            "findings": current_findings,
        }

        self.history.setdefault("scans", []).append(scan_summary)
        self.history["updated_at"] = datetime.utcnow().isoformat() + "Z"
        self._save()

    def get_history(self):
        return self.history
