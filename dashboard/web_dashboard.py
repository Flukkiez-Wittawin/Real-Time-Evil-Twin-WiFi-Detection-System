from flask import Flask, render_template, jsonify, request
import json
import os
import threading
from attacker.brute_engine import BruteEngine

app = Flask(__name__)
brute_engine = BruteEngine()

STATUS_FILE = 'data/status.json'
LOG_FILE = 'logs/app.log'
WORDLIST_FILE = 'data/wordlist.txt'

# Ensure a robust default wordlist exists for the student project
if not os.path.exists(WORDLIST_FILE):
    import random, string
    os.makedirs('data', exist_ok=True)
    
    def gen_pwd(length, chars):
        return ''.join(random.choice(chars) for _ in range(length))
    
    default_words = [
        "12345678", "password", "admin123", "qwertyui", "88888888",
        gen_pwd(8, string.digits),                 # Random 8 digits
        gen_pwd(8, string.ascii_lowercase),        # Random 8 lowercase
        gen_pwd(8, string.ascii_uppercase),        # Random 8 uppercase
        gen_pwd(8, string.ascii_letters + string.digits), # Random mixed
        "WiFi" + gen_pwd(4, string.digits),        # Common mixed pattern
        gen_pwd(10, string.digits)                 # 10 digits
    ]
    
    with open(WORDLIST_FILE, 'w') as f:
        f.write("\n".join(default_words) + "\n")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/manual')
def manual():
    return render_template('manual.html')

@app.route('/bruteforce')
def bruteforce():
    return render_template('bruteforce.html')

@app.route('/api/status')
def get_status():
    status_data = {"networks": [], "findings": []}
    if os.path.exists(STATUS_FILE):
        try:
            with open(STATUS_FILE, 'r') as f:
                status_data = json.load(f)
        except:
            pass
    
    logs = []
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, 'r') as f:
                lines = f.readlines()[-20:]
                for line in lines:
                    parts = line.split(' - ')
                    if len(parts) >= 4:
                        logs.append({
                            "time": parts[0],
                            "level": parts[2],
                            "message": parts[3].strip()
                        })
        except:
            pass
            
    status_data['logs'] = logs
    return jsonify(status_data)

@app.route('/api/brute/start', methods=['POST'])
def start_brute():
    data = request.json
    ssid = data.get('ssid')
    mode = data.get('mode', 'AI') # 'AI', 'DICTIONARY', or 'EXHAUSTIVE'
    if not ssid: return jsonify({"status": "error", "message": "No SSID provided"})
    
    def run():
        brute_engine.run_brute_force(ssid, WORDLIST_FILE, mode=mode)
        
    threading.Thread(target=run).start()
    return jsonify({"status": "success", "message": f"Attack started on {ssid}"})

@app.route('/api/brute/stop', methods=['POST'])
def stop_brute():
    brute_engine.is_running = False
    return jsonify({"status": "success", "message": "Attack stop signal sent"})

@app.route('/api/brute/status')
def brute_status():
    return jsonify({
        "is_running": brute_engine.is_running,
        "current_password": brute_engine.current_password,
        "progress": brute_engine.progress,
        "attempt_count": brute_engine.attempt_count,
        "ai_mode": brute_engine.brute_mode == "AI",
        "ai_logs": brute_engine.ai_logs
    })

def run_web_dashboard():
    app.run(host='0.0.0.0', port=5000, debug=False)

if __name__ == "__main__":
    run_web_dashboard()
