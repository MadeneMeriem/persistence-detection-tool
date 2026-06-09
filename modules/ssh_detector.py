import os
import stat
import time

# how many days before we consider a modification "recent"
RECENT_DAYS_THRESHOLD = 7

SUSPICIOUS_KEY_OPTIONS = [
    'no-pty',
    'command=',
    'permitopen=',
    'tunnel=',
    'from=',
]


def _get_home_dirs():
    homes = []
    # include root
    root_ssh = "/root/.ssh"
    if os.path.isdir(root_ssh) or True:
        homes.append(("/root", "root"))

    home_base = "/home"
    if os.path.isdir(home_base):
        try:
            for user in os.listdir(home_base):
                full = os.path.join(home_base, user)
                if os.path.isdir(full):
                    homes.append((full, user))
        except PermissionError:
            pass

    return homes


def _check_permissions(path, findings, expected_mode=0o600):
    try:
        mode = os.stat(path).st_mode & 0o777
    except PermissionError:
        return

    if mode & 0o022:  # writable by group or others
        findings.append({
            "type": "ssh",
            "severity": "HIGH",
            "file": path,
            "reason": f"insecure permissions {oct(mode)} — writable by group/others",
        })
    elif mode != expected_mode:
        findings.append({
            "type": "ssh",
            "severity": "MEDIUM",
            "file": path,
            "reason": f"unexpected permissions {oct(mode)}, expected {oct(expected_mode)}",
        })


def _check_recently_modified(path, findings):
    try:
        mtime = os.path.getmtime(path)
    except PermissionError:
        return

    days_ago = (time.time() - mtime) / 86400
    if days_ago <= RECENT_DAYS_THRESHOLD:
        findings.append({
            "type": "ssh",
            "severity": "LOW",
            "file": path,
            "reason": f"modified {days_ago:.1f} day(s) ago — recent change may warrant review",
        })


def _parse_authorized_keys(path, findings):
    try:
        with open(path) as f:
            lines = f.readlines()
    except (PermissionError, UnicodeDecodeError):
        return

    for lineno, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        line_lower = line.lower()

        # flag keys with embedded forced commands or restrictions
        # these can be used to lock a backdoor key to a specific command
        for option in SUSPICIOUS_KEY_OPTIONS:
            if line_lower.startswith(option) or f',{option}' in line_lower:
                findings.append({
                    "type": "ssh",
                    "severity": "MEDIUM",
                    "file": path,
                    "line": lineno,
                    "content": line[:120],
                    "reason": f"key with restricted option '{option}' — may be a backdoor key",
                })
                break

        # flag keys using older/weaker algorithms attackers tend to generate
        if line.split()[0] in ("ssh-dss", "ecdsa-sha2-nistp256") if line.split() else False:
            findings.append({
                "type": "ssh",
                "severity": "LOW",
                "file": path,
                "line": lineno,
                "content": line[:80] + "...",
                "reason": f"weak key type {line.split()[0]} detected",
            })


def _check_ssh_config(path, findings):
    """check sshd_config for dangerous settings"""
    try:
        with open(path) as f:
            lines = f.readlines()
    except (PermissionError, FileNotFoundError):
        return

    dangerous_settings = {
        "permitrootlogin yes": ("PermitRootLogin yes", "HIGH"),
        "permitemptypasswords yes": ("PermitEmptyPasswords yes", "HIGH"),
        "passwordauthentication yes": ("PasswordAuthentication yes", "MEDIUM"),
        "x11forwarding yes": ("X11Forwarding yes", "LOW"),
        "permitttunnel yes": ("PermitTunnel yes", "MEDIUM"),
    }

    for lineno, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        line_lower = line.lower()
        for key, (label, severity) in dangerous_settings.items():
            if line_lower == key:
                findings.append({
                    "type": "ssh_config",
                    "severity": severity,
                    "file": path,
                    "line": lineno,
                    "content": line,
                    "reason": f"dangerous sshd setting: {label}",
                })


def run():
    findings = []

    # check sshd_config
    for config_path in ["/etc/ssh/sshd_config", "/etc/sshd_config"]:
        if os.path.isfile(config_path):
            _check_ssh_config(config_path, findings)

    for home_dir, username in _get_home_dirs():
        ssh_dir = os.path.join(home_dir, ".ssh")
        auth_keys = os.path.join(ssh_dir, "authorized_keys")

        if not os.path.isdir(ssh_dir):
            continue

        # check .ssh dir permissions — should be 700
        _check_permissions(ssh_dir, findings, expected_mode=0o700)

        if os.path.isfile(auth_keys):
            _check_permissions(auth_keys, findings, expected_mode=0o600)
            _check_recently_modified(auth_keys, findings)
            _parse_authorized_keys(auth_keys, findings)

    return findings