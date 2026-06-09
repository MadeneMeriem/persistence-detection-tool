# Persistence Detection — POC Test Fixtures

These files are **harmless, read-only samples** used to test and demonstrate the detection
engine. They are **not placed in real system paths** — they live here under `poc/` for
analysis purposes only. No malicious code executes.

## How to test

The detectors scan fixed system paths (`/etc/crontab`, `/etc/systemd/system/`, etc.).
To feed these samples into the tool for a live demo, temporarily copy the relevant file
into the scanned path, run `python main.py`, then remove it.

```
# Example — cron POC
sudo cp poc/cron/poc_crontab /etc/cron.d/poc-test
python main.py
sudo rm /etc/cron.d/poc-test
```

> ⚠️  Always remove POC files from system paths after testing.

---

## POC Inventory

| File | Module | Severity | Technique simulated |
|------|--------|----------|---------------------|
| `cron/poc_crontab` | cron | HIGH | `/tmp/` execution, curl pipe to bash, base64 decode |
| `cron/poc_reverse_shell_cron` | cron | HIGH | Bash reverse shell scheduled via cron |
| `systemd/poc_backdoor.service` | systemd | HIGH | ExecStart from `/tmp/`, nohup background |
| `systemd/poc_download_exec.service` | systemd | HIGH | wget pipe to bash in a service |
| `startup/poc_bashrc_inject` | startup | HIGH | Eval of base64, curl pipe, /tmp/ execution |
| `startup/poc_profile_inject` | startup | HIGH | eval wget output, disown |
| `ssh/poc_authorized_keys` | ssh | MEDIUM | Keys with forced-command and no-pty options |
| `ssh/poc_sshd_config` | ssh | HIGH/MEDIUM | PermitRootLogin yes, PermitEmptyPasswords yes |
