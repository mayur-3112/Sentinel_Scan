import sys
import json
import os
from fpdf import FPDF

# --- Configuration ---
TASK_FILE = "task.txt"
REPORT_DIR = "reports"

# --- MOCK SCAN FUNCTIONS ---
# In your real code, these functions would execute the actual tools.
def run_nmap_scan(target_domain):
    print(f"[+] Running Nmap against {target_domain}...")
    return "Nmap scan found open ports: 21 (FTP), 80 (HTTP).", ['nmap_ftp_21', 'nmap_http_80']

def run_nikto_scan(target_domain):
    print(f"[+] Running Nikto against {target_domain}...")
    return "Nikto scan identified potential XSS.", ['nikto_xss']

def check_dns_records(target_domain):
    print(f"[+] Checking DNS for {target_domain}...")
    return "DNS records found: A, MX, TXT.", []

def check_virustotal(target_domain, api_key):
    print(f"[+] Checking VirusTotal for {target_domain}...")
    return "VirusTotal score: 0/90 (Clean).", []

def check_shodan(target_domain, api_key):
    print(f"[+] Checking Shodan for {target_domain}...")
    return f"Shodan data found for IP related to {target_domain}.", []

# --- UPGRADED REPORTING ENGINE ---
def generate_pdf_report(target_domain, nmap_data, nikto_data, dns_data, vt_data, shodan_data):
    print("[*] Generating PDF report...")
    
    nmap_output, nmap_finding_ids = nmap_data
    nikto_output, nikto_finding_ids = nikto_data
    dns_output, dns_finding_ids = dns_data
    vt_output, vt_finding_ids = vt_data
    shodan_output, shodan_finding_ids = shodan_data

    all_finding_ids = nmap_finding_ids + nikto_finding_ids + dns_finding_ids + vt_finding_ids + shodan_finding_ids

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

    # Save the report to the correct directory
    report_filename = os.path.join(REPORT_DIR, f"Security_Report_{target_domain}.pdf")
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
    
    VT_API_KEY = os.getenv("76c3d0b87388c013b3662c3cc3a4263f329ab03909866396fc2f950ea71c062b")
    SHODAN_API_KEY = os.getenv("UrGQb0cnSw7hphwUjl4iM44PaBMP6IvK")
    
    nmap_data = run_nmap_scan(target_domain)
    nikto_data = run_nikto_scan(target_domain)
    dns_data = check_dns_records(target_domain)
    vt_data = check_virustotal(target_domain, VT_API_KEY)
    shodan_data = check_shodan(target_domain, SHODAN_API_KEY)
    
    generate_pdf_report(target_domain, nmap_data, nikto_data, dns_data, vt_data, shodan_data)