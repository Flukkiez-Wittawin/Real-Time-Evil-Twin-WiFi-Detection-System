import subprocess
import re

def test_scan():
    print("--- DIAGNOSTIC SCAN START ---")
    try:
        output = subprocess.check_output(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            universal_newlines=True,
            stderr=subprocess.STDOUT
        )
        print("RAW OUTPUT LENGTH:", len(output))
        print("RAW OUTPUT PREVIEW (First 500 chars):")
        print(output[:500])
        
        # Simple count of SSID and BSSID occurrences
        ssids = re.findall(r"SSID \d+", output)
        bssids = re.findall(r"BSSID \d+", output)
        print(f"\nFOUND: {len(ssids)} SSIDs, {len(bssids)} BSSIDs")
        
    except Exception as e:
        print(f"ERROR: {e}")
    print("--- DIAGNOSTIC SCAN END ---")

if __name__ == "__main__":
    test_scan()
