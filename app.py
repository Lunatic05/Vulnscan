from flask import Flask, request, jsonify
from flask_cors import CORS
import threading
import uuid
from database import Database
from scanner import VulnScanner
import traceback

app = Flask(__name__)
CORS(app)
db = Database()
scan_jobs = {}

@app.route('/scan', methods=['POST'])
def start_scan():
    data = request.get_json()
    url = data.get('url', '').strip()
    options = data.get('options', {})
    if not url: return jsonify({'error': 'URL required'}), 400
    if not url.startswith(('http://', 'https://')): url = 'https://' + url
    scan_id = str(uuid.uuid4())[:8].upper()
    db.create_scan(scan_id, url)
    scan_jobs[scan_id] = {'status': 'running', 'progress': 0, 'logs': []}
    threading.Thread(target=_run, args=(scan_id, url, options), daemon=True).start()
    return jsonify({'scan_id': scan_id})

def _run(scan_id, url, options):
    def log(msg):
        print(msg, flush=True)
        scan_jobs[scan_id]['logs'].append(msg)

    def prog(p):
        print(f"Progress: {p}%", flush=True)
        scan_jobs[scan_id]['progress'] = p

    try:
        log(f'Target: {url}')
        log('Initializing scanner engine...')
        prog(5)

        scanner = VulnScanner(url, options)

        log('Running OWASP 2025 checks...')
        prog(20)

        result = scanner.run()

        log(f'Found {len(result.get("vulnerabilities", []))} vulnerabilities')
        prog(90)

        db.save_results(scan_id, result)

        prog(100)
        log('Scan complete. Results saved to database.')

        scan_jobs[scan_id] = {
            **result,
            'status': 'complete',
            'progress': 100,
            'logs': scan_jobs[scan_id]['logs']
        }

    except Exception as e:
        traceback.print_exc()

        scan_jobs[scan_id] = {
            'status': 'error',
            'error': str(e),
            'logs': scan_jobs.get(scan_id, {}).get('logs', [])
        }

        db.update_scan_status(scan_id, 'error')

@app.route('/scan/<scan_id>', methods=['GET'])
def get_scan(scan_id):
    if scan_id in scan_jobs:
        job = scan_jobs[scan_id]
        return jsonify({**job, 'total_vulns': len(job.get('vulnerabilities', []))})
    result = db.get_scan(scan_id)
    if result: return jsonify(result)
    return jsonify({'error': 'Not found'}), 404

@app.route('/scans', methods=['GET'])
def list_scans():
    return jsonify({'scans': db.list_scans()})

@app.route('/stats', methods=['GET'])
def get_stats():
    return jsonify(db.get_stats())

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'online', 'version': '1.0'})

if __name__ == '__main__':
    db.init()
    print('[VulnScan v1.0] Backend → http://localhost:5000')
    app.run(debug=True, port=5000, threaded=True)
