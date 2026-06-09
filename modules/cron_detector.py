import os
import re

# these combos are what attackers actually use — download and execute
HIGH_RISK_PATTERNS = [
    (r"curl\s+.+\|\s*(bash|sh|python|perl)", "download and execute via curl"),
    (r"wget\s+.+\|\s*(bash|sh|python|perl)", "download and execute via wget"),
    (r"wget\s+-O\s*-\s+.+\|\s*(bash|sh)", "download and pipe to shell"),
    (r"curl\s+-s\s+.+\|\s*(bash|sh)", "silent curl piped to shell"),
    (r"base64\s+-d\s*.*\|\s*(bash|sh|python)", "base64 decode and execute"),
    (r"(bash|sh)\s+-i\s+>&?\s*/dev/(tcp|udp)/", "reverse shell"),
    (r"nc\s+(-e|-c)\s+", "netcat with execute flag"),
    (r"python\s+-c\s+['\"]import socket", "python reverse shell"),
]

# suspicious directories in execution context only
SUSPICIOUS_PATHS = ["/tmp/", "/dev/shm/", "/var/tmp/"]

# known legit script names to skip
WHITELIST_SCRIPTS = [
    "rkhunter", "aide", "dailyaidecheck", "apt-compat",
    "man-db", "exim4", "brave-browser", "sessionclean",
]

CRON_FILES = [
    "/etc/crontab",
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
]


def _is_cron_schedule_line(line):
    # actual cron entries start with timing fields or @reboot etc.
    return bool(re.match(r'^(@\w+|\*|[\d*/,-]+)\s', line))


def _check_line(line):
    """returns (reason, severity) or None if clean"""
    line_lower = line.lower()

    for pattern, reason in HIGH_RISK_PATTERNS:
        if re.search(pattern, line_lower):
            return reason, "HIGH"

    # flag execution of binaries from suspicious paths only when the path is used as a command target
    for sus_path in SUSPICIOUS_PATHS:
        if re.search(r'(^|[\s;|&])' + re.escape(sus_path) + r'[^ \t;|&]+', line_lower):
            return f"execution from {sus_path}", "HIGH"

    return None


def _is_whitelisted(filepath):
    name = os.path.basename(filepath).lower()
    return any(w in name for w in WHITELIST_SCRIPTS)


def _scan_file(path, findings):
    if _is_whitelisted(path):
        return

    try:
        with open(path) as f:
            lines = f.readlines()
    except (PermissionError, UnicodeDecodeError):
        return

    for lineno, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        result = _check_line(line)
        if result:
            reason, severity = result
            findings.append({
                "type": "cron",
                "severity": severity,
                "file": path,
                "line": lineno,
                "content": line,
                "reason": reason,
            })


def _get_user_crontabs():
    paths = []
    spool = "/var/spool/cron/crontabs"
    if os.path.isdir(spool):
        try:
            for user in os.listdir(spool):
                paths.append(os.path.join(spool, user))
        except PermissionError:
            pass
    return paths


def run():
    findings = []

    for path in CRON_FILES:
        if os.path.isfile(path):
            _scan_file(path, findings)
        elif os.path.isdir(path):
            for entry in os.listdir(path):
                full = os.path.join(path, entry)
                if os.path.isfile(full):
                    _scan_file(full, findings)

    for path in _get_user_crontabs():
        _scan_file(path, findings)

    return findings