from utils.logger import logger
from colorama import init, Fore, Style

# Initialize colorama
init()

class AlertSystem:
    def __init__(self):
        # ANSI escape codes for colors
        self.RED = Fore.RED
        self.YELLOW = Fore.YELLOW
        self.RESET = Style.RESET_ALL
        self.BOLD = Style.BRIGHT

    def trigger(self, finding):
        severity = finding.get('severity', 'INFO')
        msg = f"[{severity}] {finding['type']}: {finding['reason']} (SSID: {finding.get('ssid')}, MAC: {finding.get('mac')})"
        
        if severity == 'CRITICAL':
            print(f"{self.RED}{self.BOLD}!!! ALERT !!! {msg}{self.RESET}")
            logger.error(msg)
        elif severity == 'WARNING':
            print(f"{self.YELLOW}!! WARNING !! {msg}{self.RESET}")
            logger.warning(msg)
        else:
            print(f"[*] {msg}")
            logger.info(msg)

    def simple_alert(self, message):
        print(f"{self.YELLOW}[!] {message}{self.RESET}")
