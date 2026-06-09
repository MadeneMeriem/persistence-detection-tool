import os
import re

# common startup files attackers modify
STARTUP_FILES = [
    "/etc/profile",
    "/etc/bash.bashrc",
    "/etc/bash.bash_logout",
    "/etc/environment",
    "/etc/rc.local",
    "/etc/rc.d/rc.local",
]

# per-user files — expanded for each user found in /home + root
PER_USER_FILES = [
    ".bashrc",
    ".bash_profile",
    ".profile",
    ".bash_logout",
    ".zshrc",
    ".zprofile",
    ".config/fish/config.fish",
    ".xinitrc",
    ".xprofile",
]

SUSPICIOUS_EXEC_PATHS = ["/tmp/", "/dev/shm/", "/var/tmp/"]

HIGH_RISK_PATTERNS = [
    (r"curl\s+.+\|\s*(bash|sh|python|perl)", "download and execute via curl", "HIGH"),
    (r"wget\s+.+\|\s*(bash|sh|python|perl)", "download and execute via wget", "HIGH"),
    (r"wget\s+-O\s*-\s+.+\|\s*(bash|sh)", "download and pipe to shell", "HIGH"),
    (r"base64\s+-d.*\|\s*(bash|sh|python)", "base64 decode and execute", "HIGH"),
    (r"bash\s+-i\s+>&?\s*/dev/(tcp|udp)/", "reverse shell", "HIGH"),
    (r"nc\s+(-e|-c)\s+", "netcat with execute flag", "HIGH"),
    (r"python\s+-c\s+['\"]import socket", "python reverse shell", "HIGH"),
    (r"eval\s+.*base64", "eval with base64 — obfuscated execution", "HIGH"),
    (r"eval\s+\$\(curl", "eval curl output", "HIGH"),
    (r"eval\s+\$\(wget", "eval wget output", "HIGH"),
    (r"nohup\s+.+&\s*$", "background execution with nohup", "LOW"),
    (r"\bdisown\b", "process disowned from shell", "LOW"),
]


def _check_line(line):
    line_lower = line.lower()

    for pattern, reason, severity in HIGH_RISK_PATTERNS:
        if re.search(pattern, line_lower):
            return reason, severity

    # executable called directly from a suspicious path
    for sus_path in SUSPICIOUS_EXEC_PATHS:
        if re.search(r'(^|[\s;|&])' + re.escape(sus_path) + r'\S+', line):
            return f"execution from {sus_path}", "HIGH"

    return None


def _scan_file(path, findings):
    try:
        with open(path) as f:
            lines = f.readlines()
    except (PermissionError, FileNotFoundError, UnicodeDecodeError):
        return

    for lineno, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        result = _check_line(line)
        if result:
            reason, severity = result
            findings.append({
                "type": "startup",
                "severity": severity,
                "file": path,
                "line": lineno,
                "content": line,
                "reason": reason,
            })


def _get_home_dirs():
    homes = ["/root"]
    home_base = "/home"
    if os.path.isdir(home_base):
        try:
            for user in os.listdir(home_base):
                full = os.path.join(home_base, user)
                if os.path.isdir(full):
                    homes.append(full)
        except PermissionError:
            pass
    return homes


def run():
    findings = []

    # scan system-wide startup files
    for path in STARTUP_FILES:
        if os.path.isfile(path):
            _scan_file(path, findings)

    # scan per-user startup files across all home dirs
    for home in _get_home_dirs():
        for rel_path in PER_USER_FILES:
            full = os.path.join(home, rel_path)
            if os.path.isfile(full):
                _scan_file(full, findings)

    return findings