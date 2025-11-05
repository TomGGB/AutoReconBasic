#!/usr/bin/env python3

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import subprocess
import threading
import uuid
import os
import re
import time
from datetime import datetime

app = Flask(__name__)
CORS(app)

# Store running jobs
jobs = {}

class ReconJob:
    def __init__(self, job_id, domain):
        self.job_id = job_id
        self.domain = domain
        self.status = 'running'
        self.phase = 0
        self.logs = []
        self.results = {}
        self.workdir = None
        self.process = None

    def add_log(self, log_type, message):
        self.logs.append({
            'type': log_type,
            'message': message,
            'timestamp': datetime.now().isoformat()
        })

def parse_output_line(line, job):
    """Parse script output and update job status"""
    if not line:
        return

    # Detect phases
    if "PHASE 1: SUBDOMAIN ENUMERATION" in line:
        job.phase = 1
        job.add_log('info', 'Phase 1: Subdomain Enumeration started')
    elif "PHASE 2: LIVE HOST DETECTION" in line:
        job.phase = 2
        job.add_log('info', 'Phase 2: Live Host Detection started')
    elif "PHASE 3: JAVASCRIPT FILE EXTRACTION" in line:
        job.phase = 3
        job.add_log('info', 'Phase 3: JavaScript Extraction started')
    elif "PHASE 4: WAYBACK MACHINE ENUMERATION" in line:
        job.phase = 4
        job.add_log('info', 'Phase 4: Wayback Machine Enumeration started')
    elif "PHASE 5: VULNERABILITY SCANNING" in line:
        job.phase = 5
        job.add_log('info', 'Phase 5: Vulnerability Scanning started')
    elif "PHASE 6: REPORT GENERATION" in line:
        job.phase = 6
        job.add_log('info', 'Phase 6: Report Generation started')

    # Detect successes
    if "[+]" in line:
        job.add_log('success', line.split('[+]', 1)[1].strip() if '[+]' in line else line)
    # Detect errors
    elif "[!]" in line or "Error:" in line:
        job.add_log('error', line.split('[!]', 1)[1].strip() if '[!]' in line else line)
    # Detect info
    elif "[*]" in line:
        job.add_log('info', line.split('[*]', 1)[1].strip() if '[*]' in line else line)

def parse_results(workdir, job):
    """Parse the summary file to extract results"""
    summary_file = os.path.join(workdir, 'reports', 'summary.txt')

    if not os.path.exists(summary_file):
        return

    try:
        with open(summary_file, 'r') as f:
            content = f.read()

        # Extract statistics using regex
        results = {}
        patterns = {
            'total_subs': r'Total Subdomains:\s+(\d+)',
            'critical_subs': r'Critical Subdomains:\s+(\d+)',
            'alive_hosts': r'Alive Hosts:\s+(\d+)',
            'js_files': r'JavaScript Files:\s+(\d+)',
            'wayback_urls': r'Wayback URLs:\s+(\d+)',
            'api_endpoints': r'API Endpoints:\s+(\d+)',
            'takeovers': r'Subdomain Takeovers:\s+(\d+)',
            'exposures': r'Exposures:\s+(\d+)',
            'cves': r'CVEs:\s+(\d+)'
        }

        for key, pattern in patterns.items():
            match = re.search(pattern, content)
            if match:
                results[key] = int(match.group(1))
            else:
                results[key] = 0

        results['workdir'] = workdir
        job.results = results

    except Exception as e:
        job.add_log('error', f'Failed to parse results: {str(e)}')

def run_recon(job):
    """Run the reconnaissance script"""
    try:
        script_path = os.path.join(os.path.dirname(__file__), 'auto_recon.sh')

        # Make sure script is executable
        os.chmod(script_path, 0o755)

        # Run the script
        process = subprocess.Popen(
            ['bash', script_path, job.domain],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1
        )

        job.process = process

        # Read output line by line
        for line in iter(process.stdout.readline, ''):
            if line:
                clean_line = re.sub(r'\x1b\[[0-9;]*m', '', line.strip())  # Remove ANSI codes
                parse_output_line(clean_line, job)

        process.wait()

        # Find the working directory
        workdirs = [d for d in os.listdir('.') if d.startswith(f"{job.domain}_recon_")]
        if workdirs:
            # Get the most recent one
            workdirs.sort(reverse=True)
            job.workdir = workdirs[0]
            parse_results(job.workdir, job)

        if process.returncode == 0:
            job.status = 'completed'
            job.add_log('success', 'Reconnaissance completed successfully!')
        else:
            job.status = 'failed'
            job.add_log('error', f'Script exited with code {process.returncode}')

    except Exception as e:
        job.status = 'failed'
        job.add_log('error', f'Error running script: {str(e)}')

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/<path:path>')
def static_files(path):
    return send_from_directory('.', path)

@app.route('/api/start', methods=['POST'])
def start_scan():
    data = request.json
    domain = data.get('domain', '').strip()

    if not domain:
        return jsonify({'success': False, 'error': 'Domain is required'}), 400

    # Validate domain
    domain_regex = r'^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}$'
    if not re.match(domain_regex, domain):
        return jsonify({'success': False, 'error': 'Invalid domain format'}), 400

    # Create job
    job_id = str(uuid.uuid4())
    job = ReconJob(job_id, domain)
    jobs[job_id] = job

    # Start scan in background thread
    thread = threading.Thread(target=run_recon, args=(job,))
    thread.daemon = True
    thread.start()

    return jsonify({
        'success': True,
        'job_id': job_id,
        'domain': domain
    })

@app.route('/api/status/<job_id>')
def get_status(job_id):
    job = jobs.get(job_id)

    if not job:
        return jsonify({'error': 'Job not found'}), 404

    # Get new logs since last check
    new_logs = job.logs.copy()
    job.logs.clear()  # Clear logs after sending

    response = {
        'status': job.status,
        'phase': job.phase,
        'logs': new_logs
    }

    if job.status == 'completed':
        response['results'] = {
            **job.results,
            'job_id': job_id
        }

    return jsonify(response)

@app.route('/api/details/<job_id>/<data_type>')
def get_details(job_id, data_type):
    job = jobs.get(job_id)

    if not job:
        return jsonify({'error': 'Job not found'}), 404

    if not job.workdir:
        return jsonify({'error': 'Data not available yet'}), 404

    # Map data types to file paths
    file_map = {
        'subdomains': 'subdomains/all_subdomains.txt',
        'critical': 'subdomains/critical_subs.txt',
        'alive': 'alive/alive_hosts.txt',
        'js': 'js/js_files.txt',
        'wayback': 'endpoints/wayback_all.txt',
        'api': 'endpoints/api_endpoints.txt',
        'takeovers': 'vulnerabilities/takeovers.txt',
        'cves': 'vulnerabilities/cves.txt',
        'exposures': 'vulnerabilities/exposures.txt'
    }

    if data_type not in file_map:
        return jsonify({'error': 'Invalid data type'}), 400

    file_path = os.path.join(job.workdir, file_map[data_type])

    try:
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                lines = f.readlines()
                # Clean lines and remove empty ones
                data = [line.strip() for line in lines if line.strip()]
                return jsonify({'data': data})
        else:
            return jsonify({'data': []})
    except Exception as e:
        return jsonify({'error': f'Error reading file: {str(e)}'}), 500

@app.route('/api/report/<job_id>')
def get_report(job_id):
    job = jobs.get(job_id)

    if not job:
        return jsonify({'error': 'Job not found'}), 404

    if not job.workdir:
        return jsonify({'error': 'Report not available yet'}), 404

    report_path = os.path.join(job.workdir, 'reports', 'recon_report.md')

    if os.path.exists(report_path):
        return send_from_directory(os.path.dirname(report_path), 'recon_report.md')
    else:
        return jsonify({'error': 'Report file not found'}), 404

@app.route('/api/jobs')
def list_jobs():
    job_list = []
    for job_id, job in jobs.items():
        job_list.append({
            'job_id': job_id,
            'domain': job.domain,
            'status': job.status,
            'phase': job.phase
        })
    return jsonify(job_list)

if __name__ == '__main__':
    print("""
╔═══════════════════════════════════════════════════════╗
║                                                       ║
║           AUTO RECON - Web Interface                 ║
║              Server Starting...                       ║
║                                                       ║
╚═══════════════════════════════════════════════════════╝

Server running on: http://localhost:5000
Press Ctrl+C to stop
    """)

    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)
