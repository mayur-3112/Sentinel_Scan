# scanner_engine.py (Final Polished Version 1.6 - Final Correction)

import subprocess
import sys
import os
import dns.resolver
import requests
import time
from datetime import datetime
from fpdf import FPDF

# --- CONFIGURATION ---
# We now define the DIRECTORY of the nikto program, not the file itself.
NIKTO_DIR = r"C:\Users\Mayur Agarwal\Desktop\Projects\nikto-master\program"
VT_API_KEY = "76c3d0b87388c013b3662c3cc3a4263f329ab03909866396fc2f950ea71c062b"


def run_nmap_scan(domain: str):
    """Runs a basic Nmap scan on the given domain and returns the output."""
    print(f"[+] Starting Nmap scan for: {domain}")
    command = ["nmap", "-F", domain]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        print(f"[+] Nmap scan for {domain} completed successfully.")
        return result.stdout
    except FileNotFoundError:
        return "[!] ERROR: 'nmap' command not found."
    except subprocess.CalledProcessError as e:
        return f"[!] ERROR: Nmap scan failed for {domain}.\n[!] Error details: {e.stderr}"

# --- THE FINAL, TRULY CORRECTED NIKTO FUNCTION ---
def run_nikto_scan(domain: str):
    """Runs a comprehensive Nikto scan from its correct working directory."""
    if not os.path.isdir(NIKTO_DIR):
        return f"[!] ERROR: Nikto directory not found at the configured path: {NIKTO_DIR}"
    
    print(f"\n[+] Starting Comprehensive Nikto scan for: {domain}")
    # The command now just calls the script name, as we will be inside its directory.
    command = ["perl", "nikto.pl", "-h", domain, "-Tuning", "4"]
    
    try:
        # THE CRITICAL CHANGE: We use the 'cwd' (current working directory) argument.
        # This tells the subprocess to run the command AS IF it were standing in the Nikto directory.
        result = subprocess.run(
            command, 
            cwd=NIKTO_DIR, # Set the working directory
            capture_output=True,
            text=True, 
            check=False 
        )
        print(f"[+] Nikto scan for {domain} completed.")
        
        # We combine both output streams to ensure we capture everything.
        full_output = result.stdout + result.stderr
        
        if not full_output.strip():
            return "Nikto scan completed with no significant findings."
            
        return full_output
        
    except FileNotFoundError:
        return "[!] ERROR: 'perl' or 'nikto.pl' command not found."
    except Exception as e:
        return f"[!] An unexpected error occurred during Nikto scan: {e}"


def check_dns_records(domain: str):
    """Checks for SPF and DMARC records for the given domain."""
    print(f"\n[+] Checking DNS records for: {domain}")
    report = []
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8']
    try:
        txt_records = resolver.resolve(domain, 'TXT')
        spf_found = any(rec.to_text().strip('"').startswith("v=spf1") for rec in txt_records)
        report.append(f"SPF Record: {'Found' if spf_found else 'NOT FOUND - Vulnerable to email spoofing!'}")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        report.append("SPF Record: NOT FOUND - Vulnerable to email spoofing!")
    try:
        dmarc_records = resolver.resolve(f"_dmarc.{domain}", 'TXT')
        dmarc_found = any(rec.to_text().strip('"').startswith("v=DMARC1") for rec in dmarc_records)
        report.append(f"DMARC Record: {'Found' if dmarc_found else 'NOT FOUND - No policy for spoofed emails!'}")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        report.append("DMARC Record: NOT FOUND - No policy for spoofed emails!")
    return "\n".join(report)

def check_virustotal(domain: str, api_key: str):
    """Checks the VirusTotal API for a domain's reputation."""
    print(f"\n[+] Checking VirusTotal reputation for: {domain}")
    if not api_key or api_key == "YOUR_VT_API_KEY_HERE":
        return "[!] ERROR: VirusTotal API key is not configured."
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": api_key}
    try:
        time.sleep(1) 
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            malicious_votes = stats.get('malicious', 0)
            harmless_votes = stats.get('harmless', 0)
            report = [f"SUCCESS: Analysis from {harmless_votes + malicious_votes} security vendors."]
            if malicious_votes > 0:
                report.append(f"  - CRITICAL FINDING: {malicious_votes} vendors flagged this domain as malicious.")
            else:
                report.append("  - All vendors reported this domain as harmless.")
            return "\n".join(report)
        else:
            return f"[!] ERROR: Received an unexpected status code from VirusTotal: {response.status_code}"
    except Exception as e:
        return f"[!] An error occurred during VirusTotal check: {e}"

def generate_pdf_report(domain: str, nmap_data, nikto_data, dns_data, vt_data):
    """Generates a memorable, professional PDF report."""
    print(f"\n[+] Generating memorable PDF report for: {domain}")
    
    class PDF(FPDF):
        def header(self):
            self.set_font("Arial", 'B', 12)
            self.cell(0, 10, 'Sentinel Scan - Professional Security Assessment', 0, 0, 'C')
            self.ln(5)
            self.set_font("Arial", '', 8)
            self.cell(0, 10, 'Automated External Reconnaissance Report', 0, 0, 'C')
            self.ln(10)

        def footer(self):
            self.set_y(-15)
            self.set_font("Arial", 'I', 8)
            self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

        def chapter_title(self, title):
            self.set_font("Arial", 'B', 12)
            self.cell(0, 6, title, 0, 1, 'L')
            self.ln(4)

        def chapter_body(self, body, font_family="Courier", font_size=8):
            self.set_font(font_family, '', font_size)
            self.multi_cell(0, 5, body)
            self.ln()

        def finding(self, title, risk, details, recommendation):
            self.set_font("Arial", 'B', 11)
            # Set color based on risk
            if risk == "Critical":
                self.set_text_color(220, 50, 50) # Red
            elif risk == "Medium":
                self.set_text_color(255, 193, 7) # Orange
            else: # Low / Informational
                self.set_text_color(40, 167, 69) # Green
            
            self.cell(0, 6, f"[{risk}] {title}", 0, 1, 'L')
            self.set_text_color(0, 0, 0) # Reset to black
            
            self.set_font("Arial", '', 10)
            self.multi_cell(0, 5, f"Details: {details}")
            self.ln(2)
            self.set_font("Arial", 'I', 10)
            self.multi_cell(0, 5, f"Recommendation: {recommendation}")
            self.ln(5)


    pdf = PDF()
    pdf.add_page()
    
    # --- Executive Summary ---
    pdf.chapter_title("Executive Summary")
    summary_text = (
        f"This report details the findings of an automated, non-intrusive security scan of the domain '{domain}' "
        f"conducted on {datetime.now().strftime('%Y-%m-%d')}. The scan focused on public-facing network services, "
        "web application configuration, email security, and public reputation. Key findings are detailed in the sections below. "
        "It is recommended to review all findings, especially those marked as 'Critical' or 'Medium'."
    )
    pdf.chapter_body(summary_text, "Arial", 10)

    # --- DNS & Email Security Section ---
    pdf.chapter_title("1. DNS & Email Security")
    if "NOT FOUND" in dns_data:
        pdf.finding(
            "Missing Email Security Records (SPF/DMARC)",
            "Critical",
            "The domain is missing critical SPF and/or DMARC DNS records. This makes the domain highly vulnerable to email spoofing, allowing attackers to send fraudulent emails that appear to come from your organization, which can lead to phishing attacks and reputation damage.",
            "Implement both SPF and DMARC records in your domain's DNS settings. This will specify which mail servers are authorized to send email on your behalf and instruct receiving mail servers on how to handle fraudulent emails."
        )
    else:
        pdf.finding(
            "Email Security Records Found",
            "Informational",
            "SPF and DMARC records were found for the domain. This is a good security practice that helps prevent email spoofing.",
            "Periodically review your SPF and DMARC policies to ensure they are up-to-date with your current email infrastructure."
        )
    pdf.chapter_body(dns_data)

    # --- Network Reconnaissance Section ---
    pdf.chapter_title("2. Network Reconnaissance (Nmap)")
    pdf.chapter_body(nmap_data)

    # --- Web Application Scan Section ---
    pdf.chapter_title("3. Web Application Scan (Nikto)")
    pdf.chapter_body(nikto_data)

    # --- VirusTotal Section ---
    pdf.chapter_title("4. Malicious Reputation (VirusTotal)")
    pdf.chapter_body(vt_data)

    report_filename = f"Professional_Security_Report_{domain}.pdf"
    pdf.output(report_filename)
    print(f"[+] Memorable report saved successfully: {report_filename}")
    return report_filename

# --- UPDATED MAIN BLOCK ---
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scanner_engine.py <domain_to_scan>")
        sys.exit(1)

    target_domain = sys.argv[1]
    
    nmap_output = run_nmap_scan(target_domain)
    nikto_output = run_nikto_scan(target_domain)
    dns_output = check_dns_records(target_domain)
    vt_output = check_virustotal(target_domain, VT_API_KEY)
    
    generate_pdf_report(target_domain, nmap_output, nikto_output, dns_output, vt_output)
# scanner_engine.py (Final Polished Version 1.6 - Final Correction)

import subprocess
import sys
import os
import dns.resolver
import requests
import time
from datetime import datetime
from fpdf import FPDF

# --- CONFIGURATION ---
# We now define the DIRECTORY of the nikto program, not the file itself.
NIKTO_DIR = r"C:\Users\Mayur Agarwal\Desktop\Projects\nikto-master\program"
VT_API_KEY = "76c3d0b87388c013b3662c3cc3a4263f329ab03909866396fc2f950ea71c062b"


def run_nmap_scan(domain: str):
    """Runs a basic Nmap scan on the given domain and returns the output."""
    print(f"[+] Starting Nmap scan for: {domain}")
    command = ["nmap", "-F", domain]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        print(f"[+] Nmap scan for {domain} completed successfully.")
        return result.stdout
    except FileNotFoundError:
        return "[!] ERROR: 'nmap' command not found."
    except subprocess.CalledProcessError as e:
        return f"[!] ERROR: Nmap scan failed for {domain}.\n[!] Error details: {e.stderr}"

# --- THE FINAL, TRULY CORRECTED NIKTO FUNCTION ---
def run_nikto_scan(domain: str):
    """Runs a comprehensive Nikto scan from its correct working directory."""
    if not os.path.isdir(NIKTO_DIR):
        return f"[!] ERROR: Nikto directory not found at the configured path: {NIKTO_DIR}"
    
    print(f"\n[+] Starting Comprehensive Nikto scan for: {domain}")
    # The command now just calls the script name, as we will be inside its directory.
    command = ["perl", "nikto.pl", "-h", domain, "-Tuning", "4"]
    
    try:
        # THE CRITICAL CHANGE: We use the 'cwd' (current working directory) argument.
        # This tells the subprocess to run the command AS IF it were standing in the Nikto directory.
        result = subprocess.run(
            command, 
            cwd=NIKTO_DIR, # Set the working directory
            capture_output=True,
            text=True, 
            check=False 
        )
        print(f"[+] Nikto scan for {domain} completed.")
        
        # We combine both output streams to ensure we capture everything.
        full_output = result.stdout + result.stderr
        
        if not full_output.strip():
            return "Nikto scan completed with no significant findings."
            
        return full_output
        
    except FileNotFoundError:
        return "[!] ERROR: 'perl' or 'nikto.pl' command not found."
    except Exception as e:
        return f"[!] An unexpected error occurred during Nikto scan: {e}"


def check_dns_records(domain: str):
    """Checks for SPF and DMARC records for the given domain."""
    print(f"\n[+] Checking DNS records for: {domain}")
    report = []
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8']
    try:
        txt_records = resolver.resolve(domain, 'TXT')
        spf_found = any(rec.to_text().strip('"').startswith("v=spf1") for rec in txt_records)
        report.append(f"SPF Record: {'Found' if spf_found else 'NOT FOUND - Vulnerable to email spoofing!'}")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        report.append("SPF Record: NOT FOUND - Vulnerable to email spoofing!")
    try:
        dmarc_records = resolver.resolve(f"_dmarc.{domain}", 'TXT')
        dmarc_found = any(rec.to_text().strip('"').startswith("v=DMARC1") for rec in dmarc_records)
        report.append(f"DMARC Record: {'Found' if dmarc_found else 'NOT FOUND - No policy for spoofed emails!'}")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        report.append("DMARC Record: NOT FOUND - No policy for spoofed emails!")
    return "\n".join(report)

def check_virustotal(domain: str, api_key: str):
    """Checks the VirusTotal API for a domain's reputation."""
    print(f"\n[+] Checking VirusTotal reputation for: {domain}")
    if not api_key or api_key == "YOUR_VT_API_KEY_HERE":
        return "[!] ERROR: VirusTotal API key is not configured."
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": api_key}
    try:
        time.sleep(1) 
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            malicious_votes = stats.get('malicious', 0)
            harmless_votes = stats.get('harmless', 0)
            report = [f"SUCCESS: Analysis from {harmless_votes + malicious_votes} security vendors."]
            if malicious_votes > 0:
                report.append(f"  - CRITICAL FINDING: {malicious_votes} vendors flagged this domain as malicious.")
            else:
                report.append("  - All vendors reported this domain as harmless.")
            return "\n".join(report)
        else:
            return f"[!] ERROR: Received an unexpected status code from VirusTotal: {response.status_code}"
    except Exception as e:
        return f"[!] An error occurred during VirusTotal check: {e}"

def generate_pdf_report(domain: str, nmap_data, nikto_data, dns_data, vt_data):
    """Generates a memorable, professional PDF report."""
    print(f"\n[+] Generating memorable PDF report for: {domain}")
    
    class PDF(FPDF):
        def header(self):
            self.set_font("Arial", 'B', 12)
            self.cell(0, 10, 'Sentinel Scan - Professional Security Assessment', 0, 0, 'C')
            self.ln(5)
            self.set_font("Arial", '', 8)
            self.cell(0, 10, 'Automated External Reconnaissance Report', 0, 0, 'C')
            self.ln(10)

        def footer(self):
            self.set_y(-15)
            self.set_font("Arial", 'I', 8)
            self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

        def chapter_title(self, title):
            self.set_font("Arial", 'B', 12)
            self.cell(0, 6, title, 0, 1, 'L')
            self.ln(4)

        def chapter_body(self, body, font_family="Courier", font_size=8):
            self.set_font(font_family, '', font_size)
            self.multi_cell(0, 5, body)
            self.ln()

        def finding(self, title, risk, details, recommendation):
            self.set_font("Arial", 'B', 11)
            # Set color based on risk
            if risk == "Critical":
                self.set_text_color(220, 50, 50) # Red
            elif risk == "Medium":
                self.set_text_color(255, 193, 7) # Orange
            else: # Low / Informational
                self.set_text_color(40, 167, 69) # Green
            
            self.cell(0, 6, f"[{risk}] {title}", 0, 1, 'L')
            self.set_text_color(0, 0, 0) # Reset to black
            
            self.set_font("Arial", '', 10)
            self.multi_cell(0, 5, f"Details: {details}")
            self.ln(2)
            self.set_font("Arial", 'I', 10)
            self.multi_cell(0, 5, f"Recommendation: {recommendation}")
            self.ln(5)


    pdf = PDF()
    pdf.add_page()
    
    # --- Executive Summary ---
    pdf.chapter_title("Executive Summary")
    summary_text = (
        f"This report details the findings of an automated, non-intrusive security scan of the domain '{domain}' "
        f"conducted on {datetime.now().strftime('%Y-%m-%d')}. The scan focused on public-facing network services, "
        "web application configuration, email security, and public reputation. Key findings are detailed in the sections below. "
        "It is recommended to review all findings, especially those marked as 'Critical' or 'Medium'."
    )
    pdf.chapter_body(summary_text, "Arial", 10)

    # --- DNS & Email Security Section ---
    pdf.chapter_title("1. DNS & Email Security")
    if "NOT FOUND" in dns_data:
        pdf.finding(
            "Missing Email Security Records (SPF/DMARC)",
            "Critical",
            "The domain is missing critical SPF and/or DMARC DNS records. This makes the domain highly vulnerable to email spoofing, allowing attackers to send fraudulent emails that appear to come from your organization, which can lead to phishing attacks and reputation damage.",
            "Implement both SPF and DMARC records in your domain's DNS settings. This will specify which mail servers are authorized to send email on your behalf and instruct receiving mail servers on how to handle fraudulent emails."
        )
    else:
        pdf.finding(
            "Email Security Records Found",
            "Informational",
            "SPF and DMARC records were found for the domain. This is a good security practice that helps prevent email spoofing.",
            "Periodically review your SPF and DMARC policies to ensure they are up-to-date with your current email infrastructure."
        )
    pdf.chapter_body(dns_data)

    # --- Network Reconnaissance Section ---
    pdf.chapter_title("2. Network Reconnaissance (Nmap)")
    pdf.chapter_body(nmap_data)

    # --- Web Application Scan Section ---
    pdf.chapter_title("3. Web Application Scan (Nikto)")
    pdf.chapter_body(nikto_data)

    # --- VirusTotal Section ---
    pdf.chapter_title("4. Malicious Reputation (VirusTotal)")
    pdf.chapter_body(vt_data)

    report_filename = f"Professional_Security_Report_{domain}.pdf"
    pdf.output(report_filename)
    print(f"[+] Memorable report saved successfully: {report_filename}")
    return report_filename

# --- UPDATED MAIN BLOCK ---
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scanner_engine.py <domain_to_scan>")
        sys.exit(1)

    target_domain = sys.argv[1]
    
    nmap_output = run_nmap_scan(target_domain)
    nikto_output = run_nikto_scan(target_domain)
    dns_output = check_dns_records(target_domain)
    vt_output = check_virustotal(target_domain, VT_API_KEY)
    
    generate_pdf_report(target_domain, nmap_output, nikto_output, dns_output, vt_output)












