import json
from utils.logger import logger
from scanner.wifi_scanner import normalize_mac
from ai.model_manager import ModelManager
from utils.vendor_lookup import VendorLookup

class WiFiAnalyzer:
    """
    v4.5 Advanced Forensic Analyzer
    Implements WPA Integrity, Cipher Downgrade, and BSSID Entropy analysis.
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
        except: return {}

    def analyze(self, scan_results):
        findings = []
        self.ai.ssid_density = {} 

        # Peer analysis maps
        overlap_map = {} # channel -> [signal, mac, ssid, threat]
        encryption_map = {} # ssid -> [auth, cipher]

        for network in scan_results:
            ssid = network['ssid'].strip()
            auth = network.get('auth', 'Unknown')
            cipher = network.get('cipher', 'Unknown')
            bssids = network['bssids']
            is_whitelisted = ssid in self.whitelist
            
            # Deep Forensic v4.5: Encryption Baseline
            if ssid not in encryption_map:
                encryption_map[ssid] = (auth, cipher)
            else:
                base_auth, base_cipher = encryption_map[ssid]
                # DETECTION: Encryption Mismatch within same SSID (Evil Twin often uses simpler auth)
                if auth != base_auth or cipher != base_cipher:
                    findings.append({
                        'type': 'ENCRYPTION_DOWNGRADE',
                        'severity': 'CRITICAL',
                        'ssid': ssid, 'mac': "MULTIPLE",
                        'reason': f"SECURITY_BREACH: SSID '{ssid}' is using mixed encryption ({base_auth}/{auth}). Potential Evil Twin Downgrade."
                    })

            for ap in bssids:
                mac = ap['mac']
                raw_mac = ap.get('raw_mac', mac)
                signal = ap['signal']
                channel = ap['channel']
                ap['auth'] = auth
                ap['cipher'] = cipher
                
                # 1. Hardware Forensic Layer
                vendor_info = self.vendor.get_vendor_info(raw_mac)
                ap['vendor'] = vendor_info['name']
                ap['vendor_address'] = vendor_info['address']
                
                # 2. Deep AI Neural Prediction
                threat_score, ai_forensics = self.ai.predict_threat(mac, ssid, channel, signal)
                
                # Deep Forensic v4.5: Add Encryption and Hardware status to AI Forensics
                if vendor_info.get('integrity_violation'):
                    ai_forensics.append("HARDWARE_SPOOF: MAC/Vendor mismatch.")
                if "WPA" in auth and "TKIP" in cipher:
                    ai_forensics.append("CIPHER_WEAKNESS: TKIP detected (Legacy/Insecure).")
                    threat_score = min(threat_score + 15, 100)

                ap['threat_score'] = threat_score
                ap['forensics'] = ai_forensics

                # 3. Hardware Integrity Check
                if vendor_info.get('integrity_violation'):
                    findings.append({
                        'type': 'HARDWARE_SPOOFING',
                        'severity': 'CRITICAL',
                        'ssid': ssid, 'mac': mac,
                        'reason': f"INTEGRITY_VIOLATION: Device {raw_mac} claims to be {vendor_info['name']} but uses a Randomized MAC bit."
                    })

                # 4. Peer-Channel Collision Logic
                if channel in overlap_map:
                    p_sig, p_mac, p_ssid, p_threat = overlap_map[channel]
                    if p_mac != mac and p_ssid == ssid and abs(signal - p_sig) < 20 and signal > 75:
                         is_p_trusted = is_whitelisted and p_mac in [normalize_mac(m) for m in self.whitelist[ssid].get('bssid', [])]
                         is_c_trusted = is_whitelisted and mac in [normalize_mac(m) for m in self.whitelist[ssid].get('bssid', [])]
                         
                         risk_threshold = 45
                         danger_detected = (threat_score > risk_threshold or p_threat > risk_threshold)
                         trust_violation = (is_p_trusted != is_c_trusted)
                         
                         if danger_detected or trust_violation:
                             findings.append({
                                'type': 'CHANNEL_HIJACK',
                                'severity': 'CRITICAL',
                                'ssid': ssid, 'mac': mac,
                                'reason': f"CHANNEL_COLLISION: High-power overlap on Ch {channel} for '{ssid}'. Trusted AP is being masked by an unknown device."
                            })
                overlap_map[channel] = (signal, mac, ssid, threat_score)

                # 5. Combined Autonomous Detection
                if threat_score > 65:
                    xai_briefing = self.ai.generate_xai_report(ssid, mac, ai_forensics, threat_score)
                    ap['strategic_intel'] = xai_briefing
                    findings.append({
                        'type': 'DEEP_AI_ALERT',
                        'severity': 'CRITICAL' if threat_score > 85 else 'WARNING',
                        'ssid': ssid, 'mac': mac,
                        'reason': f"AI_FORENSICS: {'; '.join(ai_forensics[:2])}",
                        'xai_report': xai_briefing
                    })
                else:
                    ap['strategic_intel'] = self.ai.generate_xai_report(ssid, mac, ai_forensics, threat_score)

                # 6. Whitelist Validation
                if is_whitelisted:
                    config = self.whitelist[ssid]
                    trusted_bssids = [normalize_mac(m) for m in config.get('bssid', [])]
                    # Check for Authorization
                    if mac not in trusted_bssids:
                        findings.append({
                            'type': 'WHITELIST_BREACH',
                            'severity': 'CRITICAL',
                            'ssid': ssid, 'mac': mac,
                            'reason': f"BLOCK: Unauthorized {vendor_info['name']} device hijacking secure SSID '{ssid}'."
                        })
                    # Check for Encryption consistency with Whitelist
                    expected_auth = config.get('encryption')
                    if expected_auth and expected_auth not in auth:
                         findings.append({
                            'type': 'ENCRYPTION_VIOLATION',
                            'severity': 'CRITICAL',
                            'ssid': ssid, 'mac': mac,
                            'reason': f"SEC_POLICY_FAILURE: Whitelisted SSID '{ssid}' expected '{expected_auth}' but found '{auth}'."
                        })

        return findings
