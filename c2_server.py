from flask import Flask, render_template, request, send_from_directory, redirect, url_for, jsonify
import subprocess
import os
import datetime

app = Flask(__name__)
TASK_FILE = "task.txt"
REPORT_DIR = "reports"

# --- GLOBAL VARIABLES FOR STATE TRACKING ---
SCAN_PROCESS = None
CURRENT_TARGET = ""

# Create reports directory if it doesn't exist
if not os.path.exists(REPORT_DIR):
    os.makedirs(REPORT_DIR)

@app.route('/', methods=['GET', 'POST'])
def index():
    global SCAN_PROCESS, CURRENT_TARGET
    message = None
    if request.method == 'POST':
        # Only start a scan if one is not already running
        if SCAN_PROCESS is None or SCAN_PROCESS.poll() is not None:
            target = request.form['target']
            CURRENT_TARGET = target
            with open(TASK_FILE, 'w') as f:
                f.write(target)
            print(f"[*] Tasking agent to scan: {target}")
            SCAN_PROCESS = subprocess.Popen(['python3', 'scanner_engine.py'])
            message = f"Scan initiated for {target}."
        else:
            message = "ERROR: A scan is already in progress."
    return render_template('index.html', message=message)

# --- NEW ROUTE FOR LIVE STATUS ---
@app.route('/status')
def status():
    global SCAN_PROCESS, CURRENT_TARGET
    if SCAN_PROCESS and SCAN_PROCESS.poll() is None:
        # Process is still running
        return jsonify({'status': 'scanning', 'target': CURRENT_TARGET})
    else:
        # Process is finished or was never started
        return jsonify({'status': 'idle'})

@app.route('/reports')
def list_reports():
    report_files = os.listdir(REPORT_DIR)
    reports_with_details = []
    for report in report_files:
        try:
            target = report.replace('Security_Report_', '').replace('.pdf', '').replace('_', '/')
            file_path = os.path.join(REPORT_DIR, report)
            creation_timestamp = os.path.getctime(file_path)
            creation_date = datetime.datetime.fromtimestamp(creation_timestamp).strftime('%Y-%m-%d %H:%M:%S')
            reports_with_details.append({
                'filename': report, 'target': target, 'date': creation_date
            })
        except Exception:
            reports_with_details.append({
                'filename': report, 'target': 'Unknown', 'date': 'Unknown'
            })
    reports_with_details.sort(key=lambda x: x['date'], reverse=True)
    return render_template('reports.html', reports=reports_with_details)

@app.route('/reports/<filename>')
def download_report(filename):
    return send_from_directory(REPORT_DIR, filename)

@app.route('/reports/delete/<filename>', methods=['POST'])
def delete_report(filename):
    try:
        file_path = os.path.join(REPORT_DIR, filename)
        if os.path.exists(file_path):
            os.remove(file_path)
    except Exception as e:
        print(f"[!] Error deleting file {filename}: {e}")
    return redirect(url_for('list_reports'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
