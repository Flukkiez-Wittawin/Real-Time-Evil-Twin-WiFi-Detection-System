import random
from scanner.wifi_scanner import normalize_mac

class WiFiSimulator:
    def __init__(self, target_ssid="HENG_2.4GHz"):
        self.target_ssid = target_ssid
        self.tick = 0

    def inject(self, scan_results):
        self.tick += 1
        
        # Simulate an attack with high Signal Jitter (variance)
        # Randomly fluctuate signal to trigger the AI jitter detection
        jitter_signal = 90 + random.randint(-8, 8) 

        fake_ap = {
            "ssid": self.target_ssid,
            "auth": "WPA2-Personal",
            "cipher": "CCMP",
            "bssids": [
                {
                    "mac": normalize_mac("DE:AD:BE:EF:FF:01"),
                    "raw_mac": "DE-AD-BE-EF-FF-01",
                    "signal": jitter_signal,
                    "channel": 11
                }
            ]
        }
        
        for net in scan_results:
            if net['ssid'] == self.target_ssid:
                net['bssids'].append(fake_ap['bssids'][0])
                return scan_results
        
        scan_results.append(fake_ap)
        return scan_results
