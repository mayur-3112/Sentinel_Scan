# Sentinel Scan - Automated Web Security Assessment Engine

Sentinel Scan is a powerful, automated reconnaissance tool written in Python. It is designed to perform a comprehensive, non-intrusive security assessment of a public-facing web application and deliver a professional, easy-to-understand report.

## About The Project

This project was born from a desire to move beyond theoretical knowledge and build a real-world, valuable security tool. While learning about individual vulnerabilities is important, I wanted to create an engine that could automate the entire initial phase of a security assessment, just as a professional would.

Sentinel Scan is the result. It is a testament to the power of combining professional-grade open-source tools with intelligent automation. It is the core of a freelance service I can offer, and a project I am incredibly proud of.

### Key Features

The engine performs a multi-faceted analysis from four different angles:

1.  **Network Reconnaissance:** Utilizes **Nmap** to perform a fast port scan, identifying open ports and running services on the target server.
2.  **Web Application Scanning:** Deploys **Nikto** to conduct a comprehensive scan for over 6,700 known vulnerabilities, outdated software, and server misconfigurations.
3.  **Email Security Audit:** Checks the target's **DNS records** for the presence and validity of SPF and DMARC records, assessing its defense against email spoofing and phishing attacks.
4.  **Malicious Reputation Check:** Integrates with the **VirusTotal API** to check the domain's reputation against the databases of over 60 global security vendors.
5.  **Automated PDF Reporting:** Automatically compiles all findings into a memorable, professional PDF report, complete with an executive summary and color-coded risk levels.

## Built With

* [Python](https://www.python.org/)
* [Nmap](https://nmap.org/)
* [Nikto](https://github.com/sullo/nikto)
* [VirusTotal API](https://developers.virustotal.com/reference)
* [FPDF2 (for PDF Generation)](https://pyfpdf.github.io/fpdf2/)
* [dnspython](https://dnspython.readthedocs.io/en/latest/)

## Getting Started

To get a local copy up and running in a Linux environment (like Kali), follow these simple steps.

### Prerequisites

* A Kali Linux environment (or another Debian-based Linux with Nmap and Nikto installed).
* Python 3 and pip.

### Installation & Execution

1.  Clone the repository:
    ```bash
    git clone [https://github.com/mayur-3112/Sentinel-Scan.git](https://github.com/mayur-3112/Sentinel-Scan.git)
    ```
2.  Navigate into the project directory:
    ```bash
    cd Sentinel-Scan
    ```
3.  Create and activate a virtual environment:
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```
4.  Install the required Python packages:
    ```bash
    pip install -r requirements.txt
    ```
    *(Note: You will need to create a `requirements.txt` file for this to work.)*

5.  Run the engine:
    ```bash
    python3 scanner_engine.py <target_domain>
    
