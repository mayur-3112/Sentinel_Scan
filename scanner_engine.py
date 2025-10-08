import sys
import json
import os
import subprocess
import re
import requests
import dns.resolver
from fpdf import FPDF

# --- IMPORT BRIDGE TO SPECIALIST MODULE ---
from modules.appsec_scanner import run_nikto_scan

# --- Configuration ---
TASK_FILE = "task.txt"
REPORT_DIR = "reports"

# --- INTELLIGENCE PARSERS ---

def parse_nmap_output(nmap_output):
    """Parses Nmap output to extract open ports and map them to finding IDs."""
    finding_ids = []
    port_pattern = re.compile(r"(\d+)/tcp\s+open\s+(\w+)")
    matches = port_pattern.findall(nmap_output)
    for port, service in matches:
        finding_id = f"nmap_{service}_{port}"
        finding_ids.append(finding_id)
    return nmap_output, finding_ids

def parse_nikto_output(nikto_output):
    """
    Parses Nikto's raw output to extract key vulnerabilities and map them to finding IDs.
    """
    finding_ids = []
    # This is a simple parser. A more advanced version would use more regex.
    if "OSVDB-3233" in nikto_output or "XSS" in nikto_output:
        finding_ids.append("nikto_xss")
    if "OSVDB-3092" in nikto_output or "SQL Injection" in nikto_output:
        finding_ids.append("nikto_sql_injection")

    # If no specific findings, we return an empty list.
    return nikto_output, finding_ids

# --- LIVE SCANNER MODULES ---

def run_nmap_scan(target_domain):
    """Executes a live Nmap scan and parses the results."""
    print(f"[+] Running Nmap against {target_domain}...")
    command = f"nmap -F {target_domain}"
    try:
        process = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
        print("[+] Nmap scan completed successfully.")
        return parse_nmap_output(process.stdout)
    except subprocess.CalledProcessError as e:
        error_msg = f"Nmap scan failed: {e.stderr}"
        print(f"[!] ERROR: {error_msg}")
        return error_msg, []
    except FileNotFoundError:
        error_msg = "[!] CRITICAL ERROR: 'nmap' command not found."
        print(error_msg)
        return error_msg, []

def check_dns_records(target_domain):
    """Performs live DNS lookups for common record types."""
    print(f"[+] Checking DNS for {target_domain}...")
    output = ""
    for r_type in ['A', 'AAAA', 'MX', 'TXT', 'NS']:
        try:
            answers = dns.resolver.resolve(target_domain, r_type)
            output += f"--- {r_type} Records ---\n" + "\n".join([str(rdata) for rdata in answers]) + "\n\n"
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            output += f"--- {r_type} Records ---\nNo {r_type} records found.\n\n"
    return output, []

def check_virustotal(target_domain, api_key):
    """Checks the domain's reputation using the VirusTotal API."""
    print(f"[+] Checking VirusTotal for {target_domain}...")
    if not api_key:
        return "VirusTotal check skipped: API key not set.", []
    url = f"https://www.virustotal.com/api/v3/domains/{target_domain}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        stats = response.json()['data']['attributes']['last_analysis_stats']
        return f"VirusTotal Stats: Harmless: {stats.get('harmless', 0)}, Malicious: {stats.get('malicious', 0)}, Suspicious: {stats.get('suspicious', 0)}", []
    except requests.exceptions.RequestException as e:
        return f"VirusTotal API error: {e}", []

def check_shodan(target_domain, api_key):
    """Queries Shodan for information on the domain's primary IP."""
    print(f"[+] Checking Shodan for {target_domain}...")
    if not api_key:
        return "Shodan check skipped: API key not set.", []
    try:
        ip_address = dns.resolver.resolve(target_domain, 'A')[0].to_text()
        url = f"https://api.shodan.io/shodan/host/{ip_address}?key={api_key}"
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        return (f"IP: {data.get('ip_str')}\nOrg: {data.get('org', 'N/A')}\nOpen Ports: {data.get('ports', [])}"), []
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return f"Could not resolve domain '{target_domain}' to an IP.", []
    except requests.exceptions.RequestException as e:
        return f"Shodan API error: {e}", []


# --- MARK II REPORTING ENGINE ---
def generate_pdf_report(target_domain, nmap_data, nikto_data, dns_data, vt_data, shodan_data):
    print("[*] Generating Mark II PDF report...")

    nmap_output, nmap_finding_ids = nmap_data
    nikto_output, nikto_finding_ids = nikto_data # Now receives structured data
    dns_output, _ = dns_data
    vt_output, _ = vt_data
    shodan_output, _ = shodan_data

    all_finding_ids = nmap_finding_ids + nikto_finding_ids

    try:
        with open('remediation_db.json', 'r') as f:
            remediation_db = json.load(f)
    except FileNotFoundError:
        print("[!] ERROR: remediation_db.json not found.")
        return

    risk_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for finding_id in all_finding_ids:
        if finding_id in remediation_db:
            risk = remediation_db[finding_id].get("risk", "Low")
            if risk in risk_counts:
                risk_counts[risk] += 1

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(0, 10, f'Security Assessment Report: {target_domain}', 0, 1, 'C')
    pdf.ln(10)

    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, 'Executive Summary', 0, 1)
    pdf.set_font("Arial", '', 10)
    summary_text = (
        f"This automated assessment identified a total of {len(all_finding_ids)} potential vulnerabilities. "
        f"The findings include {risk_counts['Critical']} Critical-risk, {risk_counts['High']} High-risk, "
        f"and {risk_counts['Medium']} Medium-risk issues. Immediate attention is required to address "
        "all Critical and High-risk vulnerabilities to mitigate potential impact."
    )
    pdf.multi_cell(0, 5, summary_text)
    pdf.ln(10)

    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, 'Detailed Findings & Remediation', 0, 1)

    for finding_id in all_finding_ids:
        if finding_id in remediation_db:
            advice = remediation_db[finding_id]
            pdf.set_font("Arial", 'B', 10)
            pdf.cell(0, 10, f"Finding: {advice['title']}", 0, 1)
            pdf.set_font("Arial", 'I', 10)
            pdf.cell(0, 5, f"Risk Level: {advice['risk']}", 0, 1)
            pdf.set_font("Arial", '', 10)
            pdf.multi_cell(0, 5, f"Summary: {advice['summary']}")
            pdf.multi_cell(0, 5, f"Recommended Action: {advice['remediation']}")
            pdf.ln(5)

    pdf.add_page()
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, 'Raw Scan Data', 0, 1)
    pdf.set_font("Courier", '', 8)
    pdf.multi_cell(0, 5, f"--- Nmap Output ---\n{nmap_output}")
    pdf.multi_cell(0, 5, f"\n--- Nikto Output ---\n{nikto_output}")
    pdf.multi_cell(0, 5, f"\n--- DNS Records ---\n{dns_output}")
    pdf.multi_cell(0, 5, f"\n--- VirusTotal ---\n{vt_output}")
    pdf.multi_cell(0, 5, f"\n--- Shodan ---\n{shodan_output}")

    report_filename = os.path.join(REPORT_DIR, f"Security_Report_{target_domain.replace('/', '_')}.pdf")
    pdf.output(report_filename)
    print(f"[+] Report saved as {report_filename}")

# --- MAIN EXECUTION BLOCK ---
if __name__ == "__main__":
    try:
        with open(TASK_FILE, 'r') as f:
            target_domain = f.read().strip()
        if not target_domain:
            print("[-] No target specified in task.txt. Exiting.")
            sys.exit(1)
    except FileNotFoundError:
        print(f"[-] Task file '{TASK_FILE}' not found. Exiting.")
        sys.exit(1)

    VT_API_KEY = os.getenv("VT_API_KEY")
    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

    nmap_data = run_nmap_scan(target_domain)
    # The raw output from the specialist module...
    nikto_raw_output = run_nikto_scan(target_domain)
    # ...is now fed into the intelligence parser.
    nikto_data = parse_nikto_output(nikto_raw_output)
    dns_data = check_dns_records(target_domain)
    vt_data = check_virustotal(target_domain, VT_API_KEY)
    shodan_data = check_shodan(target_domain, SHODAN_API_KEY)

    generate_pdf_report(target_domain, nmap_data, nikto_data, dns_data, vt_data, shodan_data)
