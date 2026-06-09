import os
import re

SERVICE_DIRS = [
    "/etc/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
    "/run/systemd/system",
]

# execution from these paths is almost never legit in a service
SUSPICIOUS_EXEC_PATHS = ["/tmp/", "/dev/shm/", "/var/tmp/"]

# known legit service name fragments to skip
WHITELIST_SERVICES = [
    "apt", "dpkg", "systemd", "dbus", "network", "ssh", "cron",
    "udev", "getty", "login", "user", "snapd", "plymouth", "cups",
    "avahi", "bluetooth", "pulseaudio", "pipewire", "polkit",
    "accounts", "udisks", "upower", "packagekit", "fwupd",
]

HIGH_RISK_EXEC_PATTERNS = [
    (r"curl\s+.+\|\s*(bash|sh|python|perl)", "download and execute via curl"),
    (r"wget\s+.+\|\s*(bash|sh|python|perl)", "download and execute via wget"),
    (r"base64\s+-d.*\|\s*(bash|sh|python)", "base64 decode and execute"),
    (r"bash\s+-i\s+>&?\s*/dev/(tcp|udp)/", "reverse shell"),
    (r"nc\s+(-e|-c)\s+", "netcat with execute flag"),
    (r"python\s+-c\s+['\"]import socket", "python reverse shell"),
    (r"nohup\s+.+&$", "background execution with nohup"),
]


def _is_whitelisted(service_name):
    name = service_name.lower()
    return any(w in name for w in WHITELIST_SERVICES)


def _parse_service_file(path):
    """returns dict of key=value pairs from [Service] section only"""
    fields = {}
    in_service_section = False
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line.startswith("["):
                    in_service_section = line == "[Service]"
                    continue
                if in_service_section and "=" in line and not line.startswith("#"):
                    key, _, val = line.partition("=")
                    fields[key.strip()] = val.strip()
    except (PermissionError, UnicodeDecodeError):
        pass
    return fields


def _check_exec_value(value):
    """checks an ExecStart/ExecStartPre/etc. value for suspicious content"""
    val_lower = value.lower()

    for pattern, reason in HIGH_RISK_EXEC_PATTERNS:
        if re.search(pattern, val_lower):
            return reason, "HIGH"

    for sus_path in SUSPICIOUS_EXEC_PATHS:
        if value.startswith(sus_path) or f" {sus_path}" in value:
            return f"execution from {sus_path}", "HIGH"

    return None


def _check_service(path):
    findings = []
    fields = _parse_service_file(path)

    exec_keys = ["ExecStart", "ExecStartPre", "ExecStartPost", "ExecStop", "ExecReload"]

    for key in exec_keys:
        if key not in fields:
            continue
        value = fields[key]
        result = _check_exec_value(value)
        if result:
            reason, severity = result
            findings.append({
                "type": "systemd",
                "severity": severity,
                "file": path,
                "field": key,
                "content": value,
                "reason": reason,
            })

    return findings


def run():
    findings = []
    seen = set()

    for directory in SERVICE_DIRS:
        if not os.path.isdir(directory):
            continue
        try:
            entries = os.listdir(directory)
        except PermissionError:
            continue

        for entry in entries:
            if not entry.endswith(".service"):
                continue
            if _is_whitelisted(entry):
                continue

            full_path = os.path.join(directory, entry)

            # skip symlinks pointing elsewhere (already covered by another dir)
            real = os.path.realpath(full_path)
            if real in seen:
                continue
            seen.add(real)

            if os.path.isfile(full_path):
                findings.extend(_check_service(full_path))

    return findings