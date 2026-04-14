# VulnScan 🛡️
> A lightweight DevSecOps vulnerability scanner for websites, APIs, and open ports.

Built with pure Python stdlib — no pip installs required.

---

## What It Does

| Check | Flag | What It Finds |
|---|---|---|
| Port Scan | `--ports` | Open risky ports (RDP, SSH, MySQL, Redis, MongoDB...) |
| HTTP Headers | `--headers` | Missing security headers (HSTS, CSP, X-Frame-Options...) |
| CVE Check | `--vulns` | Outdated Apache, nginx, PHP versions with known CVEs |
| TLS/SSL | `--ssl` | Certificate expiry, TLS 1.0/1.1 still enabled |
| DNS Recon | `--dns` | DNS records, zone transfer, SPF/DMARC checks |

---

## Requirements

- Python 3.8+
- `dig` command (for DNS checks)
  - Windows: install [BIND tools](https://www.isc.org/bind/)
  - Linux/Ubuntu: `sudo apt install dnsutils`
  - macOS: pre-installed

---

## Installation

No install needed. Just download `vulnscan.py` and run it.

```bash
# Clone or download
git clone https://github.com/yourhandle/vulnscan
cd vulnscan
```

---

## Usage

```bash
# Run all checks
python vulnscan.py example.com --all

# Run specific checks
python vulnscan.py example.com --ports
python vulnscan.py example.com --headers
python vulnscan.py example.com --ssl
python vulnscan.py example.com --dns
python vulnscan.py example.com --vulns

# Combine checks
python vulnscan.py example.com --ports --ssl
python vulnscan.py 192.168.1.1 --ports --headers
```

---

## Example Output

```
  PORT SCAN
  ──────────────────────────────────────────
  [  LOW   ]  Port 80/tcp open (HTTP)
              Plaintext web — should redirect to HTTPS
  [  INFO  ]  Port 443/tcp open (HTTPS)
              TLS web — expected

  HTTP HEADER ANALYSIS
  ──────────────────────────────────────────
  [  HIGH  ]  Missing: Strict-Transport-Security
              HSTS missing — forces HTTPS, prevents downgrade attacks
              Fix: Add 'Strict-Transport-Security' to your web server config
  [  OK    ]  Content-Security-Policy: frame-ancestors 'none'
  [  OK    ]  X-Frame-Options: SAMEORIGIN

  SCAN SUMMARY
  ──────────────────────────────────────────
  HIGH        ███ 1
  MEDIUM      █ 1
  LOW         ████ 3

  Report saved → vulnscan_example_com_20260331_120000.json
```

---

## Severity Levels

| Level | Meaning |
|---|---|
| `CRITICAL` | Immediate action required — serious exposure |
| `HIGH` | Fix as soon as possible |
| `MEDIUM` | Should be addressed — moderate risk |
| `LOW` | Best practice improvement |
| `INFO` | Informational — no action needed |

---

## Output / Reports

Every scan automatically saves a JSON report in the same folder:

```
vulnscan_example_com_20260331_120000.json
```

Example JSON structure:
```json
{
  "target": "example.com",
  "timestamp": "2026-03-31T12:00:00",
  "duration_seconds": 8,
  "total_findings": 5,
  "findings": [
    {
      "category": "Header",
      "severity": "HIGH",
      "title": "Missing: Strict-Transport-Security",
      "detail": "HSTS missing — forces HTTPS, prevents downgrade attacks",
      "remediation": "Add 'Strict-Transport-Security' to your web server config"
    }
  ]
}
```

---

## AWS EC2 Deployment

### 1. Launch an EC2 instance
- AMI: Ubuntu 22.04 LTS (t2.micro free tier works)
- Security Group: outbound all, inbound SSH from your IP only

### 2. Bootstrap (paste as User Data)
```bash
#!/bin/bash
apt-get update -y
apt-get install -y python3 dnsutils
git clone https://github.com/yourhandle/vulnscan /opt/vulnscan
chmod +x /opt/vulnscan/vulnscan.py
ln -s /opt/vulnscan/vulnscan.py /usr/local/bin/vulnscan
```

### 3. SSH in and run
```bash
ssh -i your-key.pem ubuntu@<EC2_PUBLIC_IP>
vulnscan example.com --all
```

### 4. Save reports to S3 (optional)
```bash
aws s3 cp vulnscan_*.json s3://your-bucket/reports/
```

---

## Known Limitations

- **Certificate false positives on Windows** — Python may fail to verify valid certs locally. If your browser shows a padlock, the cert is fine. Fix with `pip install certifi`.
- **DNS checks require `dig`** — if dig is not installed, DNS recon is skipped silently.
- **CVE detection is header-based** — version info must be exposed in `Server:` or `X-Powered-By:` headers. Use nikto or nuclei for deeper CVE scanning.
- **Not a replacement for full scanners** — for production security audits, combine with nmap, nikto, OWASP ZAP, or nuclei.

---

## Extending VulnScan

Ideas to take it further:

- **Nmap integration** — swap the port scanner with `nmap -sV` for service detection
- **Nuclei templates** — pipe findings into nuclei for CVE validation
- **Slack alerts** — webhook notification on CRITICAL findings
- **GitHub Actions** — run `vulnscan $DOMAIN --headers --ssl` on every deployment
- **Flask API** — wrap in a REST API for a web dashboard frontend

---

## Disclaimer

> This tool is for **authorised security testing only**. Only scan systems you own or have explicit written permission to test. Unauthorised scanning may be illegal in your jurisdiction.

---

## What This Project Demonstrates

- Network programming with raw sockets
- HTTP protocol internals (headers, TLS, redirects)
- Concurrent execution with `ThreadPoolExecutor`
- Security domain knowledge (CVEs, OWASP, DNS hygiene)
- CLI tooling with argparse and structured JSON reports
- AWS EC2 deployment

---

Built by [Your Name] · [github.com/yourhandle](https://github.com/yourhandle)
