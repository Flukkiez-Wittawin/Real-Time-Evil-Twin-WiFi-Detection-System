import os
from colorama import init, Fore, Style
from scanner.wifi_scanner import normalize_mac

# Initialize colorama
init()

class Dashboard:
    def __init__(self):
        self.BOLD = Style.BRIGHT
        self.GREEN = Fore.GREEN
        self.RED = Fore.RED
        self.YELLOW = Fore.YELLOW
        self.RESET = Style.RESET_ALL

    def clear(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def render(self, networks, findings, whitelist):
        self.clear()
        print(f"{self.BOLD}Real-Time WiFi Evil Twin Detection System{self.RESET}")
        print("-" * 80)
        print(f"{'SSID':<25} | {'BSSID':<18} | {'CH':<3} | {'Signal':<7} | {'Status'}")
        print("-" * 80)

        alert_map = {(f.get('ssid'), f.get('mac')): f for f in findings}

        for net in networks:
            ssid = net['ssid']
            for ap in net['bssids']:
                mac = ap['mac']
                display_mac = ap.get('raw_mac', mac)
                channel = ap['channel']
                signal = f"{ap['signal']}%"
                
                status = f"{self.GREEN}SAFE{self.RESET}"
                reason = ""
                
                # Check if this specific AP has a finding
                finding = alert_map.get((ssid, mac))
                
                if finding:
                    color = self.RED if finding['severity'] == 'CRITICAL' else self.YELLOW
                    status = f"{color}[!] {finding['type']}{self.RESET}"
                    reason = finding['reason']
                elif ssid in whitelist:
                    trusted_bssids = [normalize_mac(m) for m in whitelist[ssid].get('bssid', [])]
                    if mac not in trusted_bssids:
                         status = f"{self.RED}[!] SUSPICIOUS (MAC){self.RESET}"

                print(f"{ssid[:25]:<25} | {display_mac.upper():<18} | {channel:<3} | {signal:<7} | {status} {reason}")
        
        print("-" * 80)
        if findings:
            print(f"{self.RED}{self.BOLD}Detections:{self.RESET}")
            for f in findings:
                print(f" - {f['reason']}")
        else:
            print(f"{self.GREEN}Environment seems secure.{self.RESET}")
        print("\nPress Ctrl+C to stop monitoring.")
