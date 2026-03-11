# PHANTOM AI ENGINE - LEGACY ADAPTER
# Note: This file is kept for backward compatibility if needed, 
# but all 'Best AI' logic has been moved to ai/model_manager.py for high-performance detection.

from ai.model_manager import ModelManager

class AIDetector:
    def __init__(self):
        self.engine = ModelManager()

    def calculate_threat_score(self, ap, ssid, trusted_bssids):
        # Forward to the premium engine
        score, _ = self.engine.predict_threat(ap['mac'], ssid, ap['channel'], ap['signal'])
        return score

    def get_summary(self, findings):
        if not findings:
            return "SECURE", 0
        
        max_severity = 0
        for f in findings:
            if f['severity'] == 'CRITICAL': max_severity = max(max_severity, 95)
            elif f['severity'] == 'WARNING': max_severity = max(max_severity, 60)
            
        return ("DANGER" if max_severity > 80 else "CAUTION", max_severity)
