# Sentinel Scan: A C2-Enabled Security Reconnaissance Framework

Sentinel Scan is a security automation platform designed to accelerate the initial phases of a penetration test by over 90%. It combines a web-based Command & Control (C2) server with a remote Python agent to create a unified, automated reconnaissance workflow.

## Key Features

* **C2 Web Dashboard:** A simple Flask-based dashboard to initiate and manage scans from any browser.
* **Automated Workflow:** Integrates Nmap, Nikto, DNS enumeration, VirusTotal, and Shodan into a single, sequential scan.
* **Actionable Reporting:** Automatically generates detailed PDF reports with a high-level executive summary and actionable remediation steps for each finding.
* **Resilient & Secure:** Built with a professional Python virtual environment and secure, environment-variable-based key management.

## Architecture

The system uses a client-server model:

1.  **C2 Server (`c2_server.py`):** The Flask "brain" that serves the web dashboard and manages tasking via a simple `task.txt` file.
2.  **Remote Agent (`scanner_engine.py`):** The "hands" of the operation. A Python script that reads tasks from the C2 and executes the scan workflow on a Kali Linux environment.



## Getting Started

### Prerequisites
* Python 3.10+
* A Kali Linux or other Debian-based OS for the agent.

### Installation & Setup

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/mayur-3112/Sentinel-Scan.git](https://github.com/mayur-3112/Sentinel-Scan.git)
    cd Sentinel-Scan
    ```

2.  **Create and activate a virtual environment:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Set API Keys:**
    ```bash
    export VT_API_KEY="YOUR_VIRUSTOTAL_KEY"
    export SHODAN_API_KEY="YOUR_SHODAN_KEY"
    ```

5.  **Run the C2 Server:**
    ```bash
    python3 c2_server.py
    ```
Access the dashboard at `http://<your-kali-ip>:5000`.
    
