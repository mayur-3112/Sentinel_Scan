# Sentinel Scan | AppSec Module v2.2
# This module contains functions for web application vulnerability scanning.
# Calibrated for resilience in unstable network environments.

import subprocess
import logging
import shlex
import os

# --- CONFIGURATION ---
NIKTO_PATH = "/usr/bin/nikto" 

# --- INITIALIZATION ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')

def run_nikto_scan(target_url: str) -> str:
    """
    Executes a calibrated Nikto scan, tuned for stability.
    """
    logging.info(f"Initiating CALIBRATED Nikto scan against {target_url}...")
    
    if not (os.path.exists(NIKTO_PATH) and os.access(NIKTO_PATH, os.X_OK)):
        error_msg = f"CRITICAL ERROR: Nikto executable not found or not executable at '{NIKTO_PATH}'."
        logging.error(error_msg)
        return error_msg

    # THE UPGRADE: We add '-timeout 120' to give the connection up to 120 seconds 
    # before failing. This makes the scan more patient and resilient against
    # unstable target servers.
    command_str = f"{NIKTO_PATH} -h {target_url} -timeout 120"
    command = shlex.split(command_str)
    
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        stdout, stderr = process.communicate()
        
        if process.returncode != 0:
            error_msg = f"Nikto scan finished with a non-zero exit code ({process.returncode}).\n\n--- STDOUT ---\n{stdout}\n\n--- STDERR ---\n{stderr}"
            logging.warning(error_msg)
            # Even with an error, we return stdout because it often contains partial results.
            return stdout + "\n" + error_msg

        logging.info(f"Calibrated Nikto scan for {target_url} completed successfully.")
        return stdout

    except Exception as e:
        error_msg = f"An unexpected error occurred while trying to run Nikto: {str(e)}"
        logging.error(error_msg)
        return error_msg

if __name__ == "__main__":
    test_target = "http://testphp.vulnweb.com/" 
    
    print("--- [TEST] Running standalone test for AppSec module v2.2 (Calibrated) ---")
    scan_output = run_nikto_scan(test_target)
    
    print("\n--- [TEST] Scan Output ---")
    print(scan_output)
    print("--- [TEST] Test complete ---")


