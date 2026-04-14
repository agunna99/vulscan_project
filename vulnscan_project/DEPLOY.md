# VulnScan — AWS EC2 Deployment Guide

## Quick Start (Local)

```bash
# No dependencies beyond stdlib + dig (bind-utils)
python3 vulnscan.py example.com --all

# Targeted checks
python3 vulnscan.py example.com --ports --headers
python3 vulnscan.py 192.168.1.10 --ports --ssl
```

---

## AWS EC2 Deployment

### 1. Launch Instance
- **AMI**: Ubuntu 22.04 LTS (free tier: t2.micro)
- **Security Group**: allow outbound all; inbound SSH (22) from your IP only
- **IAM Role**: attach `AmazonS3FullAccess` (optional — for report upload)

### 2. Bootstrap Script (paste as EC2 User Data)

```bash
#!/bin/bash
apt-get update -y
apt-get install -y python3 python3-pip dnsutils nmap git
pip3 install flask flask-cors          # for optional web UI
git clone https://github.com/yourhandle/vulnscan /opt/vulnscan
chmod +x /opt/vulnscan/vulnscan.py
ln -s /opt/vulnscan/vulnscan.py /usr/local/bin/vulnscan
echo "VulnScan ready" > /var/log/vulnscan_init.log
```

### 3. SSH & Run
```bash
ssh -i your-key.pem ubuntu@<EC2_PUBLIC_IP>
vulnscan example.com --all
```

### 4. Upload Reports to S3 (optional)
```bash
aws s3 cp vulnscan_*.json s3://your-bucket/reports/
```

---

## Optional Flask Web API

Drop this in `api.py` alongside `vulnscan.py`:

```python
from flask import Flask, request, jsonify
from flask_cors import CORS
import subprocess, json, glob, os

app = Flask(__name__)
CORS(app)

@app.route("/scan", methods=["POST"])
def scan():
    data = request.json
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "target required"}), 400

    flags = ["python3", "vulnscan.py", target]
    for f in ("ports", "headers", "vulns", "ssl", "dns"):
        if data.get(f):
            flags.append(f"--{f}")
    if not any(data.get(f) for f in ("ports","headers","vulns","ssl","dns")):
        flags.append("--all")

    subprocess.run(flags, timeout=60)

    reports = sorted(glob.glob(f"vulnscan_{target.replace('.','_')}*.json"), reverse=True)
    if reports:
        with open(reports[0]) as fp:
            return jsonify(json.load(fp))
    return jsonify({"error": "scan failed"}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
```

Run: `python3 api.py`
Call: `POST http://<EC2_IP>:5000/scan`  body: `{"target":"example.com","all":true}`

---

## Nmap Integration (deeper port scan)

If `nmap` is installed, swap the port scanner section with:

```python
import subprocess, json

def run_nmap(target):
    cmd = ["nmap", "-sV", "-T4", "--top-ports", "1000",
           "--script", "vuln", "-oJ", "-", target]
    result = subprocess.run(cmd, capture_output=True, text=True)
    # parse result.stdout as nmap JSON
    return result.stdout
```

---

## Resume / Portfolio Notes

**What this demonstrates:**
- Network programming (raw socket connection testing)
- HTTP protocol internals (headers, TLS, redirects)
- Concurrent execution (ThreadPoolExecutor for port scanning)
- Security domain knowledge (CVEs, OWASP headers, DNS hygiene)
- CLI tooling (argparse, ANSI output, structured JSON reports)
- AWS deployment (EC2, S3, User Data scripts)
- REST API wrapping (Flask)

**Extend it:**
- Add nuclei template integration for CVE scanning
- Add Shodan API lookup for passive recon
- Slack/PagerDuty webhook on CRITICAL findings
- GitHub Actions workflow: `vulnscan $DOMAIN --headers --ssl` on every deploy
