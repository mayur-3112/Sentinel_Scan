# command_center.py
# The Flask web interface for the Sentinel Scan engine, now with remote execution!

from flask import Flask, render_template_string, request, jsonify
import paramiko # <-- IMPORT THE SSH LIBRARY

app = Flask(__name__)

# --- SSH Configuration ---
# IMPORTANT: Replace these with your Kali VM's details.
KALI_IP = '192.168.29.174'  # The IP of your Kali VM
KALI_USER = 'kali'          # Your username on Kali
KALI_PASS = 'kali'          # Your password on Kali

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sentinel Scan Command Center</title>
    <style>
        body {
            font-family: 'Courier New', monospace;
            background-color: #0d1117;
            color: #c9d1d9;
            margin: 0;
            padding: 20px;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .container {
            width: 100%;
            max-width: 700px;
            background-color: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 30px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
        }
        h1 {
            color: #58a6ff;
            text-align: center;
            border-bottom: 1px solid #30363d;
            padding-bottom: 15px;
            margin-top: 0;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 8px;
            color: #8b949e;
        }
        input[type="text"] {
            width: calc(100% - 20px);
            padding: 10px;
            background-color: #010409;
            border: 1px solid #30363d;
            border-radius: 6px;
            color: #c9d1d9;
            font-size: 16px;
        }
        button {
            width: 100%;
            padding: 12px;
            background-color: #238636;
            color: white;
            border: none;
            border-radius: 6px;
            font-size: 18px;
            cursor: pointer;
            transition: background-color 0.2s;
        }
        button:disabled {
            background-color: #238636;
            opacity: 0.5;
            cursor: not-allowed;
        }
        .output {
            margin-top: 25px;
            background-color: #010409;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 15px;
            min-height: 100px;
            white-space: pre-wrap;
            word-wrap: break-word;
            font-size: 14px;
            color: #8b949e;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Sentinel Scan Command Center</h1>
        <form id="scan-form">
            <div class="form-group">
                <label for="target">Target Domain:</label>
                <input type="text" id="target" name="target" placeholder="e.g., example.com" required>
            </div>
            <button type="submit" id="scan-button">Launch Scan</button>
        </form>
        <div class="output" id="output-box">
            Scan results will appear here...
        </div>
    </div>

    <script>
        document.getElementById('scan-form').addEventListener('submit', function(event) {
            event.preventDefault();
            const target = document.getElementById('target').value;
            const outputBox = document.getElementById('output-box');
            const scanButton = document.getElementById('scan-button');

            outputBox.style.color = '#c9d1d9';
            outputBox.textContent = `Connecting to remote scanner and initializing scan for ${target}...`;
            scanButton.disabled = true;
            scanButton.textContent = 'Scanning...';

            // This is the new part! We send the target to our own backend.
            fetch('/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ target: target }),
            })
            .then(response => response.json())
            .then(data => {
                // Display the result from the backend.
                outputBox.textContent = data.output;
                if (data.status === 'error') {
                    outputBox.style.color = '#f85149'; // Red for errors
                }
            })
            .catch((error) => {
                outputBox.style.color = '#f85149';
                outputBox.textContent = 'Error connecting to the command center: ' + error;
            })
            .finally(() => {
                scanButton.disabled = false;
                scanButton.textContent = 'Launch Scan';
            });
        });
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

# This is the new backend route that does the real work.
@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    target = data.get('target')

    if not target:
        return jsonify({'status': 'error', 'output': 'Error: No target domain provided.'})

    try:
        # Create an SSH client
        ssh = paramiko.SSHClient()
        # Automatically add the server's host key (less secure, but fine for our lab)
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Connect to the Kali machine
        ssh.connect(KALI_IP, username=KALI_USER, password=KALI_PASS, timeout=10)
        
        # --- THE FINAL, CORRECTED COMMAND ---
        # We now use the correct folder name with an UNDERSCORE.
        command = f"/home/kali/Sentinel_Scan/venv/bin/python3 /home/kali/Sentinel_Scan/scanner_engine.py {target}"
        
        # Execute the command
        stdin, stdout, stderr = ssh.exec_command(command)
        
        # Read the output
        output = stdout.read().decode()
        error = stderr.read().decode()
        
        # Close the connection
        ssh.close()

        if error:
            return jsonify({'status': 'error', 'output': f"Error from scanner:\\n{error}"})
        else:
            # For now, we just return a success message.
            # In the future, we could have it return the PDF report link.
            return jsonify({'status': 'success', 'output': f"Scan for {target} completed successfully!\\nCheck your Kali machine in the /home/kali/Sentinel_Scan/ directory for the PDF report."})

    except Exception as e:
        return jsonify({'status': 'error', 'output': f"An error occurred while trying to connect or run the scan:\\n{str(e)}"})

if __name__ == '__main__':
    app.run(debug=True)
