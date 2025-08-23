from flask import Flask, render_template, request, send_from_directory
import subprocess
import os

app = Flask(__name__)
# A simple way to store our one task
TASK_FILE = "task.txt"
REPORT_DIR = "reports"

# Create reports directory if it doesn't exist
if not os.path.exists(REPORT_DIR):
    os.makedirs(REPORT_DIR)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        target = request.form['target']
        # Write the new target to our task file
        with open(TASK_FILE, 'w') as f:
            f.write(target)

        # Run the scanner agent in the background
        # NOTE: This assumes c2_server.py and scanner_engine.py are in the same directory
        # on the Kali machine.
        print(f"[*] Tasking agent to scan: {target}")
        subprocess.Popen(['python3', 'scanner_engine.py'])

        return render_template('index.html', message=f"Scan initiated for {target}. Check back for the report.")

    return render_template('index.html', message=None)

@app.route('/reports')
def list_reports():
    reports = os.listdir(REPORT_DIR)
    return render_template('reports.html', reports=reports)

@app.route('/reports/<filename>')
def download_report(filename):
    return send_from_directory(REPORT_DIR, filename)


if __name__ == '__main__':
    # This will make the server accessible from other machines on your network
    app.run(host='0.0.0.0', port=5000, debug=True)