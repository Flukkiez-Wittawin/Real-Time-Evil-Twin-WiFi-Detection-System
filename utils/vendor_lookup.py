import re

class VendorLookup:
    def __init__(self):
        # OUI Database - Expanded for v4.0 Forensic Analysis
        self.oui_db = {
            "6C:44:2A": {"name": "TP-Link", "address": "Shenzhen, China"},
            "94:28:6F": {"name": "Cisco Systems", "address": "San Jose, CA, USA"},
            "AC:2G:15": {"name": "Apple, Inc.", "address": "Cupertino, CA, USA"},
            "CC:2D:1B": {"name": "Intel Corporate", "address": "Santa Clara, CA, USA"},
            "44:2A:8F": {"name": "TP-Link", "address": "Shenzhen, China"},
            "06:9A:9D": {"name": "Unknown/Virtual", "address": "Cloud/Hidden"},
            "DE:AD:BE": {"name": "ROGUE-SIMULATOR", "address": "Digital Reality"},
            "24:6F:28": {"name": "Espressif", "address": "Shanghai, China"},
            "AC:D5:64": {"name": "Espressif", "address": "Shanghai, China"},
            "D8:07:B6": {"name": "D-Link", "address": "Taipei, Taiwan"},
            "BC:CF:CC": {"name": "Xiaomi", "address": "Beijing, China"}
        }

    def get_vendor_info(self, mac):
        """
        Extracts OUI and checks for MAC randomization/spoofing.
        """
        clean_mac = mac.replace('-', ':').upper()
        parts = clean_mac.split(':')
        oui = ":".join(parts[:3])
        
        info = self.oui_db.get(oui, {"name": "Generic Vendor", "address": "Global/Unknown"})
        
        # v4.0 Hardware Integrity: Check if the MAC bit 2 of the first octet is set (Locally Administered)
        # Randomized/Spoofed MACs often have this bit set.
        try:
            first_octet = int(parts[0], 16)
            is_locally_administered = (first_octet & 0b00000010) != 0
            is_multicast = (first_octet & 0b00000001) != 0
            
            info['is_randomized'] = is_locally_administered
            info['is_multicast'] = is_multicast
            
            # If locally administered but claims to be a known vendor, that's a mismatch
            if is_locally_administered and info['name'] != "Generic Vendor" and info['name'] != "ROGUE-SIMULATOR":
                info['integrity_violation'] = True
            else:
                info['integrity_violation'] = False
                
        except:
            info['is_randomized'] = False
            info['integrity_violation'] = False

        return info
