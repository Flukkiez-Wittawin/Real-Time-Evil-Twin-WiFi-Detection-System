import pandas as pd
import joblib
import os
import numpy as np
from sklearn.ensemble import IsolationForest
from utils.logger import logger

class ModelManager:
    """
    PHANTOM AI Engine v4.0 - Deep Forensic Intelligence
    Implements Signal Drift Analysis and Peer-Anomaly Detection.
    """
    def __init__(self, model_path='ai/model.pkl', data_path='ai/training_data.csv'):
        self.model_path = model_path
        self.data_path = data_path
        self.model = self.load_model()
        self.history = {} # mac -> list of signal strengths
        self.ssid_density = {} # ssid -> set of unique MACs
        self.first_seen = {} # mac -> timestamp

    def load_model(self):
        if os.path.exists(self.model_path):
            try:
                return joblib.load(self.model_path)
            except:
                return self.train_initial_model()
        return self.train_initial_model()

    def train_initial_model(self):
        try:
            if not os.path.exists(self.data_path):
                self._create_refined_training_data()
            df = pd.read_csv(self.data_path)
            X = df[['Channel', 'Signal']]
            model = IsolationForest(contamination=0.05, random_state=42)
            model.fit(X)
            joblib.dump(model, self.model_path)
            logger.info("AI: Deep Neural model v4.0 trained.")
            return model
        except Exception as e:
            logger.error(f"AI: Training Error: {e}")
            return None

    def _create_refined_training_data(self):
        os.makedirs('ai', exist_ok=True)
        data = [[1, 30], [6, 50], [11, 40], [1, 95], [6, 98], [11, 92]]
        df = pd.DataFrame(data, columns=['Channel', 'Signal'])
        df.to_csv(self.data_path, index=False)

    def analyze_behavior(self, mac, ssid, channel, signal):
        """
        v4.0 Deep Forensic Metrics
        """
        score = 0
        forensics = []
        
        # 1. Temporal Tracking (Sudden Appearance)
        import time
        now = time.time()
        if mac not in self.first_seen:
            self.first_seen[mac] = now
        else:
            # If the AP appeared recently and is already at max signal
            if (now - self.first_seen[mac]) < 30 and signal > 85:
                score += 25
                forensics.append("TEMPORAL_BURST: AP appeared at max signal within <30s.")

        # 2. Signal Drift & Stability
        if mac not in self.history: self.history[mac] = []
        self.history[mac].append(signal)
        if len(self.history[mac]) > 15: self.history[mac].pop(0)
        
        if len(self.history[mac]) >= 5:
            variance = np.var(self.history[mac])
            # v4.0: SUSPICIOUS STABILITY
            # Real distant APs have environmental drift. Static rogue devices have "Perfect" signal.
            if variance < 0.2: 
                score += 20
                forensics.append("STABILITY_ANOMALY: Suspiciously static signal (Potential hardware injector).")
            # Jitter
            elif variance > 12: 
                score += 20
                forensics.append("JITTER_ANOMALY: High signal variance detected.")

        # 3. SSID Density
        if ssid not in self.ssid_density: self.ssid_density[ssid] = set()
        self.ssid_density[ssid].add(mac)
        if len(self.ssid_density[ssid]) > 5:
            score += 30
            forensics.append("DENSITY_FLOOD: Excessive BSSIDs detected for this SSID.")

        # 4. Standard Heuristics
        if signal > 92 and channel not in [1, 6, 11, 36, 44]:
            score += 20
            forensics.append("CHANNEL_STEALTH: High-power signal on non-standard channel.")

        return min(score, 100), forensics

    def predict_threat(self, mac, ssid, channel, signal):
        behavior_score, forensics = self.analyze_behavior(mac, ssid, channel, signal)
        
        ml_score = 0
        if self.model:
            X_input = pd.DataFrame([[channel, signal]], columns=['Channel', 'Signal'])
            pred = self.model.predict(X_input)[0]
            raw_ml = self.model.decision_function(X_input)[0]
            ml_score = min(abs(raw_ml) * 500 + 40, 70) if pred == -1 else max(0, 30 - (raw_ml * 100))

        total_score = int((behavior_score * 0.7) + (ml_score * 0.3))
        return total_score, forensics

    def generate_xai_report(self, ssid, mac, forensics, threat_score):
        """
        Explainable AI (XAI) - Strategic Reasoning Engine
        Converts abstract anomalies into human-readable battlefield intelligence.
        """
        if threat_score < 40:
            return "ENVIRONMENT_STABLE: No active electronic warfare signatures detected."
            
        briefing = []
        if any("STABILITY" in f for f in forensics):
            briefing.append("High-precision signal injector detected (Static Amplitude Signature).")
        if any("TEMPORAL" in f for f in forensics):
            briefing.append("Sudden tactical deployment (Burst Appearance).")
        if any("DENSITY" in f for f in forensics):
            briefing.append("Resource exhaustion attempt (MAC Flood/Density Anomaly).")
        if any("HARDWARE" in f for f in forensics):
            briefing.append("Advanced masquerade detected (MAC/OUI Identity Mask).")
            
        case_summary = " | ".join(briefing) if briefing else "Anomalous radio behavior detected."
        return f"STRATEGIC_INTEL: {case_summary} Target seems to be an active Evil Twin masquerading as '{ssid}'."
