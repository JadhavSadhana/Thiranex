import socket
import requests
import os
from datetime import datetime
from urllib.parse import urlparse

# ============================================================
# VULNERABILITY SCANNER - LOCALHOST MINI PROJECT
# ============================================================

TARGET = "127.0.0.1"

# Common ports used for demonstration
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Proxy/Development",
    8443: "HTTPS-Development"
}

# Small demonstration database.
# In a production scanner, this would be replaced by
# a maintained vulnerability database.
OUTDATED_VERSIONS = {
    "Apache/2.2": "Very old Apache version. Upgrade to a supported release.",
    "nginx/1.14": "Old nginx version. Upgrade to a supported release.",
    "PHP/5.": "PHP 5 is end-of-life. Upgrade to a supported PHP version."
}

# Security headers that are useful for web applications
SECURITY_HEADERS = [
    "X-Content-Type-Options",
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "Referrer-Policy"
]

results = {
    "target": TARGET,
    "open_ports": [],
    "web_checks": [],
    "version_checks": [],
    "vulnerabilities": []
}


# ============================================================
# UTILITY FUNCTIONS
# ============================================================

def add_vulnerability(title, severity, description, recommendation):
    vulnerability = {
        "title": title,
        "severity": severity,
        "description": description,
        "recommendation": recommendation
    }

    results["vulnerabilities"].append(vulnerability)


# ============================================================
# PORT SCANNER
# ============================================================

def scan_ports():
    print("\n" + "=" * 55)
    print("PORT SCANNING")
    print("=" * 55)

    for port, service in COMMON_PORTS.items():

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)

        try:
            connection = sock.connect_ex((TARGET, port))

            if connection == 0:

                print(f"[OPEN]   Port {port:<5} {service}")

                results["open_ports"].append({
                    "port": port,
                    "service": service
                })

                # Some ports deserve attention
                if port in [21, 23, 445, 3389]:
                    add_vulnerability(
                        f"Potentially risky exposed service: {service}",
                        "MEDIUM",
                        f"Port {port} ({service}) is accessible on localhost.",
                        "Disable the service if it is not required and restrict access."
                    )

            else:
                print(f"[CLOSED] Port {port:<5} {service}")

        except Exception as error:
            print(f"[ERROR] Port {port}: {error}")

        finally:
            sock.close()


# ============================================================
# WEB SERVER SCANNER
# ============================================================

def scan_web_server():

    print("\n" + "=" * 55)
    print("WEB SECURITY CHECK")
    print("=" * 55)

    urls = [
        "http://127.0.0.1",
        "http://127.0.0.1:5000",
        "http://127.0.0.1:8000",
        "http://127.0.0.1:8080"
    ]

    for url in urls:

        try:
            response = requests.get(
                url,
                timeout=2,
                allow_redirects=False
            )

            print(f"\n[FOUND] Web server: {url}")
            print(f"Status Code: {response.status_code}")

            server = response.headers.get("Server", "Not disclosed")

            print(f"Server: {server}")

            results["web_checks"].append({
                "url": url,
                "status": response.status_code,
                "server": server
            })

            # ------------------------------------------------
            # Check security headers
            # ------------------------------------------------

            for header in SECURITY_HEADERS:

                if header not in response.headers:

                    print(f"[MISSING] {header}")

                    add_vulnerability(
                        f"Missing security header: {header}",
                        "LOW",
                        f"The web application at {url} does not return the {header} header.",
                        f"Configure the {header} security header."
                    )

                else:

                    print(f"[OK] {header}")

            # ------------------------------------------------
            # Check server version
            # ------------------------------------------------

            check_server_version(server)

            return

        except requests.exceptions.RequestException:
            continue


# ============================================================
# VERSION CHECK
# ============================================================

def check_server_version(server):

    print("\n" + "-" * 55)
    print("SOFTWARE VERSION CHECK")
    print("-" * 55)

    if server == "Not disclosed":

        print("[INFO] Server version is not disclosed.")

        results["version_checks"].append({
            "server": server,
            "status": "Not disclosed"
        })

        return

    print(f"Detected server: {server}")

    found_old_version = False

    for old_version, message in OUTDATED_VERSIONS.items():

        if old_version.lower() in server.lower():

            found_old_version = True

            print(f"[WARNING] Possible outdated software: {server}")

            results["version_checks"].append({
                "server": server,
                "status": "Potentially outdated",
                "message": message
            })

            add_vulnerability(
                f"Potentially outdated software: {server}",
                "HIGH",
                message,
                "Upgrade to a currently supported version."
            )

    if not found_old_version:

        print("[OK] No version matched the demonstration outdated-version database.")

        results["version_checks"].append({
            "server": server,
            "status": "No match found"
        })


# ============================================================
# RISK SCORE
# ============================================================

def calculate_risk():

    score = 0

    for vulnerability in results["vulnerabilities"]:

        severity = vulnerability["severity"]

        if severity == "HIGH":
            score += 3

        elif severity == "MEDIUM":
            score += 2

        elif severity == "LOW":
            score += 1

    if score == 0:
        return "LOW"

    elif score <= 3:
        return "LOW"

    elif score <= 7:
        return "MEDIUM"

    else:
        return "HIGH"


# ============================================================
# HTML REPORT
# ============================================================

def generate_report():

    os.makedirs("reports", exist_ok=True)

    risk = calculate_risk()

    filename = datetime.now().strftime(
        "reports/vulnerability_report_%Y%m%d_%H%M%S.html"
    )

    html = f"""
<!DOCTYPE html>
<html>

<head>

<meta charset="UTF-8">

<title>Vulnerability Scanner Report</title>

<style>

body {{
    font-family: Arial, sans-serif;
    background: #f4f6f8;
    margin: 0;
    padding: 30px;
}}

.container {{
    max-width: 1000px;
    margin: auto;
    background: white;
    padding: 30px;
    border-radius: 12px;
}}

h1 {{
    color: #1f2937;
}}

h2 {{
    margin-top: 30px;
    color: #374151;
}}

.info {{
    background: #eef2ff;
    padding: 15px;
    border-radius: 8px;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 15px;
}}

th, td {{
    padding: 12px;
    border-bottom: 1px solid #ddd;
    text-align: left;
}}

th {{
    background: #f3f4f6;
}}

.HIGH {{
    color: #b91c1c;
    font-weight: bold;
}}

.MEDIUM {{
    color: #c2410c;
    font-weight: bold;
}}

.LOW {{
    color: #15803d;
    font-weight: bold;
}}

.risk {{
    font-size: 24px;
    font-weight: bold;
}}

</style>

</head>

<body>

<div class="container">

<h1>Vulnerability Scanner Report</h1>

<div class="info">

<p><strong>Target:</strong> {results["target"]}</p>

<p><strong>Scan Time:</strong>
{datetime.now().strftime("%d %B %Y, %I:%M:%S %p")}
</p>

<p class="risk">
Overall Risk: {risk}
</p>

</div>


<h2>1. Open Ports</h2>

<table>

<tr>
<th>Port</th>
<th>Service</th>
</tr>
"""

    if results["open_ports"]:

        for item in results["open_ports"]:

            html += f"""
<tr>
<td>{item["port"]}</td>
<td>{item["service"]}</td>
</tr>
"""

    else:

        html += """
<tr>
<td colspan="2">No common open ports detected.</td>
</tr>
"""

    html += """
</table>


<h2>2. Web Security Checks</h2>

<table>

<tr>
<th>URL</th>
<th>Status</th>
<th>Server</th>
</tr>
"""

    if results["web_checks"]:

        for item in results["web_checks"]:

            html += f"""
<tr>
<td>{item["url"]}</td>
<td>{item["status"]}</td>
<td>{item["server"]}</td>
</tr>
"""

    else:

        html += """
<tr>
<td colspan="3">No local web server detected.</td>
</tr>
"""

    html += """
</table>


<h2>3. Vulnerabilities</h2>

<table>

<tr>
<th>Severity</th>
<th>Vulnerability</th>
<th>Description</th>
<th>Recommendation</th>
</tr>
"""

    if results["vulnerabilities"]:

        for vulnerability in results["vulnerabilities"]:

            html += f"""
<tr>

<td class="{vulnerability["severity"]}">
{vulnerability["severity"]}
</td>

<td>
{vulnerability["title"]}
</td>

<td>
{vulnerability["description"]}
</td>

<td>
{vulnerability["recommendation"]}
</td>

</tr>
"""

    else:

        html += """
<tr>
<td colspan="4">No vulnerabilities detected.</td>
</tr>
"""

    html += """
</table>


<h2>4. Version Checks</h2>

<table>

<tr>
<th>Detected Server</th>
<th>Status</th>
</tr>
"""

    if results["version_checks"]:

        for item in results["version_checks"]:

            html += f"""
<tr>
<td>{item["server"]}</td>
<td>{item["status"]}</td>
</tr>
"""

    else:

        html += """
<tr>
<td colspan="2">No web server version detected.</td>
</tr>
"""

    html += """
</table>

</div>

</body>
</html>
"""

    with open(filename, "w", encoding="utf-8") as file:
        file.write(html)

    print("\n" + "=" * 55)
    print("REPORT GENERATED")
    print("=" * 55)

    print(f"Report: {filename}")


# ============================================================
# MAIN PROGRAM
# ============================================================

def main():

    print("\n")
    print("=" * 55)
    print("        LOCALHOST VULNERABILITY SCANNER")
    print("=" * 55)

    print(f"\nTarget: {TARGET}")

    print(
        "\nThis scanner is restricted to localhost for "
        "educational testing."
    )

    scan_ports()

    scan_web_server()

    risk = calculate_risk()

    print("\n" + "=" * 55)
    print("SCAN SUMMARY")
    print("=" * 55)

    print(f"Open ports: {len(results['open_ports'])}")

    print(
        f"Vulnerabilities: "
        f"{len(results['vulnerabilities'])}"
    )

    print(f"Overall risk: {risk}")

    generate_report()


if __name__ == "__main__":
    main()