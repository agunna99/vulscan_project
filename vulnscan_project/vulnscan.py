#!/usr/bin/env python3
"""
VulnScan - Lightweight DevSecOps Vulnerability Scanner
Usage: python vulnscan.py <target> [--ports] [--headers] [--vulns] [--ssl] [--dns] [--all]
"""

import argparse
import socket
import ssl
import subprocess
import sys
import json
import re
import concurrent.futures
from datetime import datetime
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

# ─── ANSI Color Codes ─────────────────────────────────────────────────────────
R = "\033[91m"; Y = "\033[93m"; G = "\033[92m"; C = "\033[96m"
M = "\033[95m"; B = "\033[94m"; W = "\033[97m"; DIM = "\033[2m"; RST = "\033[0m"
BOLD = "\033[1m"

BANNER = f"""{C}
  ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
  ██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██║   ██║██║   ██║██║     ██╔██╗ ██║███████╗██║     ███████║██╔██╗ ██║
  ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║╚════██║██║     ██╔══██║██║╚██╗██║
   ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████║╚██████╗██║  ██║██║ ╚████║
    ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{RST}{DIM}  DevSecOps Vulnerability Scanner  |  github.com/agunna99/vulnscan_project{RST}
"""

# ─── Security Headers to Check ────────────────────────────────────────────────
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "sev": "HIGH",
        "msg": "HSTS missing — forces HTTPS, prevents downgrade attacks",
    },
    "Content-Security-Policy": {
        "sev": "HIGH",
        "msg": "CSP missing — enables XSS and data injection attacks",
    },
    "X-Frame-Options": {
        "sev": "MEDIUM",
        "msg": "Clickjacking protection absent",
    },
    "X-Content-Type-Options": {
        "sev": "MEDIUM",
        "msg": "MIME sniffing protection missing (set to 'nosniff')",
    },
    "Referrer-Policy": {
        "sev": "LOW",
        "msg": "Referrer leakage possible",
    },
    "Permissions-Policy": {
        "sev": "LOW",
        "msg": "Browser feature permissions not restricted",
    },
}

LEAKY_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]

# ─── Common Ports to Scan ─────────────────────────────────────────────────────
COMMON_PORTS = {
    21:  ("FTP",     "HIGH",   "File transfer — often anonymous login risk"),
    22:  ("SSH",     "MEDIUM", "Secure shell — brute-force risk if exposed"),
    23:  ("Telnet",  "CRITICAL","Unencrypted remote access — never expose"),
    25:  ("SMTP",    "MEDIUM", "Mail relay — check for open relay"),
    53:  ("DNS",     "LOW",    "DNS — check for zone transfer"),
    80:  ("HTTP",    "LOW",    "Plaintext web — should redirect to HTTPS"),
    110: ("POP3",    "HIGH",   "Unencrypted mail retrieval"),
    143: ("IMAP",    "HIGH",   "Unencrypted mail access"),
    443: ("HTTPS",   "INFO",   "TLS web — expected"),
    445: ("SMB",     "CRITICAL","Windows file share — EternalBlue / ransomware risk"),
    1433: ("MSSQL",  "HIGH",   "Database port publicly exposed"),
    3306: ("MySQL",  "HIGH",   "Database port publicly exposed"),
    3389: ("RDP",    "HIGH",   "Remote Desktop — brute-force / BlueKeep risk"),
    5432: ("PostgreSQL","HIGH","Database port publicly exposed"),
    5900: ("VNC",    "HIGH",   "Unencrypted remote desktop"),
    6379: ("Redis",  "CRITICAL","Cache/DB often unauthenticated"),
    8080: ("HTTP-alt","MEDIUM","Dev server or proxy — likely unintended exposure"),
    8443: ("HTTPS-alt","LOW",  "Alternate HTTPS port"),
    27017: ("MongoDB","CRITICAL","Database often unauthenticated by default"),
}

SEV_COLOR = {"CRITICAL": R, "HIGH": R, "MEDIUM": Y, "LOW": G, "INFO": C}
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

findings = []


def log(msg, color=W):
    print(f"{color}{msg}{RST}")


def header(title):
    w = 60
    print(f"\n{B}{'─' * w}{RST}")
    print(f"{BOLD}{W}  {title}{RST}")
    print(f"{B}{'─' * w}{RST}")


def add_finding(category, severity, title, detail, remediation=""):
    findings.append({
        "category": category,
        "severity": severity,
        "title": title,
        "detail": detail,
        "remediation": remediation,
    })
    color = SEV_COLOR.get(severity, W)
    badge = f"{color}[{severity:^8}]{RST}"
    print(f"  {badge}  {W}{title}{RST}")
    print(f"           {DIM}{detail}{RST}")
    if remediation:
        print(f"           {G}Fix: {remediation}{RST}")


# ─── 1. Port Scanner ──────────────────────────────────────────────────────────
def scan_port(host, port):
    try:
        with socket.create_connection((host, port), timeout=1):
            return port, True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return port, False


def run_port_scan(target):
    header("PORT SCAN")
    log(f"  Scanning {len(COMMON_PORTS)} common ports on {target}...", DIM)

    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(scan_port, target, p): p for p in COMMON_PORTS}
        for future in concurrent.futures.as_completed(futures):
            port, is_open = future.result()
            if is_open:
                open_ports.append(port)

    if not open_ports:
        log("  No common ports open (or host is unreachable)", G)
        return

    for port in sorted(open_ports):
        service, sev, note = COMMON_PORTS.get(port, ("Unknown", "MEDIUM", "Unexpected service"))
        add_finding(
            "Port",
            sev,
            f"Port {port}/tcp open ({service})",
            note,
            f"Close or firewall port {port} if not required"
            if sev in ("CRITICAL", "HIGH") else "",
        )


# ─── 2. HTTP Header Scanner ───────────────────────────────────────────────────
def fetch_headers(target):
    for scheme in ("https", "http"):
        url = f"{scheme}://{target}"
        try:
            req = Request(url, headers={"User-Agent": "VulnScan/1.0"})
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            resp = urlopen(req, context=ctx, timeout=8)
            return dict(resp.headers), scheme, resp.geturl()
        except Exception:
            continue
    return None, None, None


def run_header_scan(target):
    header("HTTP HEADER ANALYSIS")
    log(f"  Fetching headers from {target}...", DIM)

    headers, scheme, final_url = fetch_headers(target)
    if not headers:
        log("  Could not reach target over HTTP/HTTPS", Y)
        return

    log(f"  {G}Connected via {scheme.upper()} → {final_url}{RST}")

    # Check missing security headers
    for h, meta in SECURITY_HEADERS.items():
        if h not in headers:
            add_finding(
                "Header",
                meta["sev"],
                f"Missing: {h}",
                meta["msg"],
                f"Add '{h}' to your web server / reverse proxy config",
            )
        else:
            print(f"  {G}[  OK    ]{RST}  {h}: {DIM}{headers[h][:60]}{RST}")

    # Check leaky headers
    for h in LEAKY_HEADERS:
        if h in headers:
            add_finding(
                "Header",
                "LOW",
                f"Version disclosure: {h}",
                f"Value: {headers[h]}",
                f"Remove or suppress the '{h}' response header",
            )

    # HTTP → HTTPS redirect check
    if scheme == "http":
        add_finding(
            "Header",
            "HIGH",
            "No HTTPS redirect",
            "Target responded on plain HTTP without redirect",
            "Configure 301 redirect to HTTPS and enable HSTS",
        )


# ─── 3. SSL/TLS Check ─────────────────────────────────────────────────────────
def run_ssl_check(target):
    header("TLS / SSL ANALYSIS")
    log(f"  Probing TLS configuration on {target}:443...", DIM)

    # Check certificate validity and expiry
    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.create_connection((target, 443), timeout=5),
                               server_hostname=target)
        cert = conn.getpeercert()
        conn.close()

        # Expiry check
        exp_str = cert.get("notAfter", "")
        if exp_str:
            exp_dt = datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (exp_dt - datetime.utcnow()).days
            if days_left < 0:
                add_finding("TLS", "CRITICAL", "Certificate EXPIRED",
                            f"Expired {abs(days_left)} days ago",
                            "Renew certificate immediately")
            elif days_left < 14:
                add_finding("TLS", "HIGH", f"Certificate expires in {days_left} days",
                            f"Expires: {exp_str}",
                            "Renew certificate immediately — consider Let's Encrypt auto-renewal")
            elif days_left < 30:
                add_finding("TLS", "MEDIUM", f"Certificate expires soon ({days_left} days)",
                            f"Expires: {exp_str}", "Schedule certificate renewal")
            else:
                print(f"  {G}[  OK    ]{RST}  Certificate valid for {days_left} more days")

    except ssl.SSLCertVerificationError as e:
        add_finding("TLS", "HIGH", "Certificate validation failed",
                    str(e), "Fix certificate chain or use a trusted CA")
    except Exception as e:
        log(f"  Could not connect to port 443: {e}", Y)
        return

    # Check for weak protocol support (TLS 1.0 / 1.1)
    for proto, ver in [("TLS 1.0", ssl.TLSVersion.TLSv1),
                       ("TLS 1.1", ssl.TLSVersion.TLSv1_1)]:
        try:
            ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            ctx2.maximum_version = ver
            conn2 = ctx2.wrap_socket(socket.create_connection((target, 443), timeout=3),
                                     server_hostname=target)
            conn2.close()
            add_finding("TLS", "MEDIUM", f"{proto} supported",
                        f"Server accepts legacy {proto} connections",
                        f"Disable {proto} in your server config")
        except Exception:
            print(f"  {G}[  OK    ]{RST}  {proto} not supported")


# ─── 4. DNS Reconnaissance ───────────────────────────────────────────────────
def run_dns_recon(target):
    header("DNS RECONNAISSANCE")
    log(f"  Enumerating DNS records for {target}...", DIM)

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
    for rtype in record_types:
        try:
            result = subprocess.run(
                ["dig", "+short", rtype, target],
                capture_output=True, text=True, timeout=5
            )
            if result.stdout.strip():
                for line in result.stdout.strip().splitlines():
                    print(f"  {C}[{rtype:^6}]{RST}  {line}")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    # Zone transfer attempt
    try:
        result = subprocess.run(
            ["dig", "AXFR", target, f"@ns1.{target}"],
            capture_output=True, text=True, timeout=5
        )
        if "XFR size" in result.stdout or len(result.stdout) > 300:
            add_finding("DNS", "CRITICAL", "Zone transfer allowed (AXFR)",
                        f"Full zone data exposed for {target}",
                        "Restrict AXFR to authorised secondary nameservers only")
        else:
            print(f"  {G}[  OK    ]{RST}  Zone transfer (AXFR) not allowed")
    except Exception:
        pass

    # SPF record check
    try:
        result = subprocess.run(
            ["dig", "+short", "TXT", target],
            capture_output=True, text=True, timeout=5
        )
        if "v=spf1" not in result.stdout:
            add_finding("DNS", "MEDIUM", "SPF record missing",
                        "Domain can be spoofed for phishing / spam",
                        "Add a TXT record: v=spf1 include:... -all")
        else:
            print(f"  {G}[  OK    ]{RST}  SPF record present")

        if "v=DMARC1" not in result.stdout:
            add_finding("DNS", "MEDIUM", "DMARC record missing",
                        "No email authentication policy enforced",
                        "Add _dmarc TXT: v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com")
    except Exception:
        pass


# ─── 5. Basic CVE / Version Checks ───────────────────────────────────────────
def run_vuln_checks(target):
    header("VULNERABILITY CHECKS")
    log("  Checking for known vulnerable service versions...", DIM)

    headers_data, scheme, _ = fetch_headers(target)
    if not headers_data:
        log("  Skipping — could not reach target", Y)
        return

    server = headers_data.get("Server", "")
    powered = headers_data.get("X-Powered-By", "")

    vuln_patterns = [
        (r"Apache/2\.4\.(0|[1-3]\d|4[0-9])\b",
         "Apache < 2.4.50 — CVE-2021-41773 path traversal",
         "Upgrade to Apache 2.4.52+"),
        (r"Apache/2\.[0-3]\b",
         "End-of-life Apache version",
         "Upgrade to current stable Apache release"),
        (r"nginx/1\.(1[0-7]|[0-9])\b",
         "Outdated nginx — potential unpatched CVEs",
         "Upgrade to nginx 1.24.0+"),
        (r"OpenSSL/1\.(0|1\.0)",
         "OpenSSL 1.0.x — EOL, many known CVEs",
         "Upgrade to OpenSSL 3.x"),
        (r"PHP/[45]\b",
         "End-of-life PHP version exposed",
         "Upgrade to PHP 8.2+"),
        (r"PHP/7\.[0-3]\b",
         "PHP 7.x EOL — no security patches",
         "Upgrade to PHP 8.2+"),
    ]

    found_any = False
    for pattern, title, fix in vuln_patterns:
        for header_val in (server, powered):
            if re.search(pattern, header_val, re.IGNORECASE):
                add_finding("CVE", "HIGH", title,
                            f"Detected via Server header: {header_val}", fix)
                found_any = True

    if not found_any:
        print(f"  {G}[  OK    ]{RST}  No obvious vulnerable versions detected in headers")
        print(f"  {DIM}Note: Run nikto/nuclei for deeper CVE scanning{RST}")


# ─── Report ───────────────────────────────────────────────────────────────────
def print_report(target, start_time):
    elapsed = (datetime.now() - start_time).seconds
    header("SCAN SUMMARY")

    by_sev = {}
    for f in findings:
        by_sev.setdefault(f["severity"], []).append(f)

    total = len(findings)
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        count = len(by_sev.get(sev, []))
        if count:
            color = SEV_COLOR[sev]
            print(f"  {color}{sev:10}{RST}  {'█' * min(count, 30)} {count}")

    print(f"\n  {DIM}Target: {target}  |  Findings: {total}  |  Duration: {elapsed}s{RST}")

    # JSON export
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"vulnscan_{target.replace('.','_')}_{ts}.json"
    report = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "duration_seconds": elapsed,
        "total_findings": total,
        "findings": sorted(findings,
                           key=lambda x: SEV_ORDER.get(x["severity"], 9)),
    }
    with open(fname, "w") as fp:
        json.dump(report, fp, indent=2)
    print(f"\n  {G}Report saved → {fname}{RST}")


# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="VulnScan — DevSecOps Vulnerability Scanner",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("target", help="Domain or IP to scan (e.g. example.com)")
    parser.add_argument("--ports",   action="store_true", help="Port scan")
    parser.add_argument("--headers", action="store_true", help="HTTP header analysis")
    parser.add_argument("--vulns",   action="store_true", help="CVE / version checks")
    parser.add_argument("--ssl",     action="store_true", help="TLS/SSL audit")
    parser.add_argument("--dns",     action="store_true", help="DNS reconnaissance")
    parser.add_argument("--all",     action="store_true", help="Run all checks")
    args = parser.parse_args()

    # Default: run all if no flag specified
    run_all = args.all or not any([args.ports, args.headers, args.vulns, args.ssl, args.dns])

    target = args.target.removeprefix("https://").removeprefix("http://").rstrip("/")
    log(f"  Target: {W}{target}{RST}", DIM)
    log(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", DIM)

    start = datetime.now()

    if run_all or args.ports:   run_port_scan(target)
    if run_all or args.headers: run_header_scan(target)
    if run_all or args.vulns:   run_vuln_checks(target)
    if run_all or args.ssl:     run_ssl_check(target)
    if run_all or args.dns:     run_dns_recon(target)

    print_report(target, start)


if __name__ == "__main__":
    main()
