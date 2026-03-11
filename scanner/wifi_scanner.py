import subprocess
import re
from utils.logger import logger

def normalize_mac(mac):
    """Removes separators and lowercases the MAC address."""
    return re.sub(r'[^a-f0-9]', '', mac.lower())

class WiFiScanner:
    def __init__(self):
        self.interface = "Wi-Fi" # Default Windows interface name

    def scan(self):
        """
        Executes netsh wlan show networks mode=bssid and parses the result.
        """
        try:
            # Run the netsh command
            result = subprocess.check_output(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                errors='ignore',
                universal_newlines=True,
                stderr=subprocess.STDOUT
            )
            return self._parse_netsh_output(result)
        except subprocess.CalledProcessError as e:
            logger.error(f"Error scanning WiFi: {e.output}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error during scan: {e}")
            return []

    def _parse_netsh_output(self, output):
        networks = []
        current_network = {}
        
        # Split output into lines and process
        lines = output.split('\n')
        
        # Regex patterns
        ssid_pattern = re.compile(r"^SSID \d+ : (.*)")
        bssid_pattern = re.compile(r"^\s+BSSID \d+\s+: (.*)")
        signal_pattern = re.compile(r"^\s+Signal\s+: (\d+)%")
        channel_pattern = re.compile(r"^\s+Channel\s+: (\d+)")
        auth_pattern = re.compile(r"^\s+Authentication\s+: (.*)")
        cipher_pattern = re.compile(r"^\s+Cipher\s+: (.*)")

        for line in lines:
            line = line.strip('\r')
            
            # Match SSID (indicates start of a new network block)
            ssid_match = ssid_pattern.match(line)
            if ssid_match:
                if current_network:
                    networks.append(current_network)
                current_network = {
                    'ssid': ssid_match.group(1).strip(),
                    'bssids': []
                }
                continue
                
            if current_network:
                # Match Authentication
                auth_match = auth_pattern.match(line)
                if auth_match:
                    current_network['auth'] = auth_match.group(1).strip()
                    continue

                # Match Cipher
                cipher_match = cipher_pattern.match(line)
                if cipher_match:
                    current_network['cipher'] = cipher_match.group(1).strip()
                    continue

                # Match BSSID block (MAC, Signal, Channel)
                bssid_match = bssid_pattern.match(line)
                if bssid_match:
                    raw_mac = bssid_match.group(1).strip()
                    current_bssid = {
                        'mac': normalize_mac(raw_mac),
                        'raw_mac': raw_mac,
                        'signal': 0,
                        'channel': 0
                    }
                    current_network['bssids'].append(current_bssid)
                    continue
                
                # Match Signal for the last added BSSID
                signal_match = signal_pattern.match(line)
                if signal_match and current_network['bssids']:
                    current_network['bssids'][-1]['signal'] = int(signal_match.group(1))
                    continue
                
                # Match Channel for the last added BSSID
                channel_match = channel_pattern.match(line)
                if channel_match and current_network['bssids']:
                    current_network['bssids'][-1]['channel'] = int(channel_match.group(1))
                    continue

        if current_network:
            networks.append(current_network)
            
        return networks

if __name__ == "__main__":
    # Test scan
    scanner = WiFiScanner()
    results = scanner.scan()
    for net in results:
        print(f"SSID: {net['ssid']} | Auth: {net.get('auth')} | BSSIDs: {len(net['bssids'])}")
        for b in net['bssids']:
            print(f"  MAC: {b['mac']} | Signal: {b['signal']}% | Channel: {b['channel']}")
