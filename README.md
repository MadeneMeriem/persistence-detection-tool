# Linux Persistence Detection

A simple Linux persistence detector with a web dashboard.
It finds suspicious cron, systemd, startup, and SSH persistence patterns and shows results in a modern UI.

## What it does

- scans common persistence locations on Linux
- writes a JSON report to `reports/findings.json`
- serves a live dashboard at `http://localhost:5051`
- exports findings as JSON, CSV, or PDF

## Install

```bash
cd /home/meriem/cyber-projects/persistance-detection-tool
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Run the scanner

```bash
python3 main.py
```

This generates `reports/findings.json` and saves a simple report file.

## Run the dashboard

```bash
python3 backend/app.py
```

Open `http://localhost:5051` in your browser.

## Test using POC samples

The `poc/` folder contains harmless sample persistence fixtures.
Copy one into the scanned path, run the scanner, then remove it.

Example for cron:

```bash
sudo cp poc/cron/poc_crontab /etc/cron.d/poc-test
python3 main.py
sudo rm /etc/cron.d/poc-test
```

## Notes

- Use the project on a test system or inside a lab environment.
- Remove POC files after testing.
