import json
from utils.logger import logger
from scanner.wifi_scanner import normalize_mac
from ai.model_manager import ModelManager
from utils.vendor_lookup import VendorLookup

class WiFiAnalyzer:
    """
    Advanced Analysis Layer
    Integrates Hybrid AI, Hardware Fingerprinting, and Whitelist verification.
    """
    def __init__(self, whitelist_path='data/whitelist.json'):
        self.whitelist_path = whitelist_path
        self.whitelist = self._load_whitelist()
        self.ai = ModelManager()
        self.vendor = VendorLookup()

    def _load_whitelist(self):
        try:
            with open(self.whitelist_path, 'r') as f:
                data = json.load(f)
                return data.get('TRUSTED_NETWORKS', {})
        except Exception:
            return {}

    def analyze(self, scan_results):
        findings = []
        
        # Reset density counts for each sweep to keep it real-time
        self.ai.ssid_density = {} 

        for network in scan_results:
            ssid = network['ssid'].strip()
            bssids = network['bssids']
            is_whitelisted_ssid = ssid in self.whitelist
            
            for ap in bssids:
                mac = ap['mac']
                raw_mac = ap.get('raw_mac', mac)
                signal = ap['signal']
                channel = ap['channel']
                
                # 1. Hardware Intelligence (Organization Intel)
                vendor_info = self.vendor.get_vendor_info(raw_mac)
                ap['vendor'] = vendor_info['name']
                ap['vendor_address'] = vendor_info['address']
                
                # 2. Hybrid AI Neural Prediction
                threat_score, is_ml_anomaly = self.ai.predict_threat(mac, ssid, channel, signal)
                ap['threat_score'] = threat_score

                # 3. Autonomous AI Detection (Detects Rogue behavior without Whitelist)
                if threat_score > 65:
                    severity = 'CRITICAL' if threat_score > 80 else 'WARNING'
                    findings.append({
                        'type': 'AI_ROGUE_DETECTION',
                        'severity': severity,
                        'ssid': ssid,
                        'mac': mac,
                        'reason': f"{severity}: AI Unified engine detects {threat_score}% malicious behavior on SSID '{ssid}'."
                    })

                # 4. Whitelist Intelligence (Optional Secondary Verification)
                if is_whitelisted_ssid:
                    config = self.whitelist[ssid]
                    trusted_bssids = [normalize_mac(m) for m in config.get('bssid', [])]
                    
                    if mac not in trusted_bssids:
                        findings.append({
                            'type': 'WHITELIST_VIOLATION',
                            'severity': 'CRITICAL',
                            'ssid': ssid,
                            'mac': mac,
                            'reason': f"CRITICAL: Unauthorized {ap['vendor']} device on whitelisted SSID '{ssid}'."
                        })
                    elif is_ml_anomaly and signal > 90:
                         findings.append({
                            'type': 'SIGNAL_HIJACK',
                            'severity': 'WARNING',
                            'ssid': ssid,
                            'mac': mac,
                            'reason': f"ALERT: Trusted {ap['vendor']} AP showing high-power signal anomaly."
                        })

        return findings
