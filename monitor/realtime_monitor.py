import time
from scanner.wifi_scanner import WiFiScanner
from scanner.simulator import WiFiSimulator
from analyzer.wifi_analyzer import WiFiAnalyzer
from alerts.alert_system import AlertSystem
from dashboard.dashboard import Dashboard
from utils.logger import logger
import os

class RealTimeMonitor:
    def __init__(self, interval=5, simulate=True):
        self.scanner = WiFiScanner()
        self.simulator = WiFiSimulator() if simulate else None
        self.analyzer = WiFiAnalyzer()
        self.alerts = AlertSystem()
        self.dashboard = Dashboard()
        self.interval = interval
        self.running = False

    def start(self):
        self.running = True
        logger.info("Universal Cyber SOC Monitor started.")
        try:
            while self.running:
                networks = self.scanner.scan()
                
                # Injected Mock Attack for Demo
                if self.simulator:
                    networks = self.simulator.inject(networks)
                
                findings = self.analyzer.analyze(networks)
                
                for f in findings:
                    self.alerts.trigger(f)
                
                self.save_status(networks, findings)
                self.dashboard.render(networks, findings, self.analyzer.whitelist)
                
                time.sleep(self.interval)
        except KeyboardInterrupt:
            self.stop()

    def save_status(self, networks, findings):
        import json
        
        # Calculate Global Threat level based on max findings
        global_threat = 0
        status_label = "SECURE"
        
        if findings:
            global_threat = 95 if any(f['severity'] == 'CRITICAL' for f in findings) else 45
            status_label = "DANGER" if global_threat > 80 else "CAUTION"
            
        data = {
            "networks": networks,
            "findings": findings,
            "system_status": status_label,
            "global_threat": global_threat,
            "timestamp": time.time()
        }
        with open('data/status.json', 'w') as f:
            json.dump(data, f)

    def stop(self):
        self.running = False
        logger.info("System Shutdown.")
