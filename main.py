from monitor.realtime_monitor import RealTimeMonitor
from dashboard.web_dashboard import run_web_dashboard
import sys
import threading

def main():
    print("========================================")
    print("   WiFi Evil Twin Detector Started      ")
    print("========================================")
    print("[*] Console Dashboard: Active")
    print("[*] Web Dashboard: http://localhost:5000")
    print("========================================")
    
    # Start Web Dashboard in a background thread
    web_thread = threading.Thread(target=run_web_dashboard, daemon=True)
    web_thread.start()
    
    # Start Monitor in main thread
    # Set simulate=False to only scan REAL-WORLD networks
    monitor = RealTimeMonitor(interval=5, simulate=False)
    
    try:
        monitor.start()
    except Exception as e:
        print(f"Critical System Failure: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
