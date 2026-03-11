class VendorLookup:
    def __init__(self):
        # A small dictionary of common OUI (Organizationally Unique Identifiers)
        # In a production system, this would be a full database or an API call.
        # Expanded OUI Database with Organization Addresses
        self.oui_db = {
            "6C:44:2A": {"name": "TP-Link", "address": "Shenzhen, China"},
            "94:28:6F": {"name": "Cisco Systems", "address": "San Jose, CA, USA"},
            "AC:2G:15": {"name": "Apple, Inc.", "address": "Cupertino, CA, USA"},
            "CC:2D:1B": {"name": "Intel Corporate", "address": "Santa Clara, CA, USA"},
            "44:2A:8F": {"name": "TP-Link", "address": "Shenzhen, China"},
            "06:9A:9D": {"name": "Unknown/Virtual", "address": "Cloud/Hidden"},
            "DE:AD:BE": {"name": "ROGUE-SIMULATOR", "address": "Digital Reality"},
            "24:6F:28": {"name": "Espressif", "address": "Shanghai, China"},
            "AC:D5:64": {"name": "Espressif", "address": "Shanghai, China"}
        }

    def get_vendor_info(self, mac):
        """
        Extracts the OUI and returns {name, address}.
        """
        clean_mac = mac.replace('-', ':').upper()
        oui = ":".join(clean_mac.split(':')[:3])
        info = self.oui_db.get(oui, {"name": "Generic Vendor", "address": "Global/Unknown"})
        return info
