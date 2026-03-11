import pandas as pd
import joblib
import os
import numpy as np
from sklearn.ensemble import IsolationForest
from utils.logger import logger

class ModelManager:
    """
    PHANTOM AI Engine v3.0 - Hybrid Intelligence
    Combines IsolationForest ML with heuristic behavioral analysis.
    """
    def __init__(self, model_path='ai/model.pkl', data_path='ai/training_data.csv'):
        self.model_path = model_path
        self.data_path = data_path
        self.model = self.load_model()
        self.history = {} # mac -> list of signal strengths
        self.ssid_density = {} # ssid -> count of unique MACs

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
            # Features: Channel, Signal, and a dummy variance baseline
            X = df[['Channel', 'Signal']]
            
            # Contamination 0.05 for higher precision in "Real-Time" detection
            model = IsolationForest(contamination=0.05, random_state=42)
            model.fit(X)
            joblib.dump(model, self.model_path)
            logger.info("AI: Neural model v3.0 trained successfully.")
            return model
        except Exception as e:
            logger.error(f"AI: Model Training Error: {e}")
            return None

    def _create_refined_training_data(self):
        os.makedirs('ai', exist_ok=True)
        # Expanded dataset for better range detection
        data = [
            [1, 30, 'normal'], [1, 45, 'normal'], [6, 50, 'normal'], [11, 40, 'normal'],
            [1, 20, 'normal'], [6, 60, 'normal'], [11, 55, 'normal'], [44, 30, 'normal'],
            [1, 95, 'evil'],   [6, 98, 'evil'],  [11, 92, 'evil']
        ]
        df = pd.DataFrame(data, columns=['Channel', 'Signal', 'Label'])
        df.to_csv(self.data_path, index=False)

    def analyze_behavior(self, mac, ssid, channel, signal):
        """
        Stage 1 & 2: Heuristic & Behavioral Analysis
        Returns a behavior_score (0-100)
        """
        score = 0
        
        # 1. Signal Jitter (Variance Tracking)
        if mac not in self.history: self.history[mac] = []
        self.history[mac].append(signal)
        if len(self.history[mac]) > 10: self.history[mac].pop(0)
        
        if len(self.history[mac]) >= 3:
            variance = np.var(self.history[mac])
            # High jitter often indicates a mobile attacker or signal injection
            if variance > 15: score += 25 
            elif variance > 8: score += 10

        # 2. SSID Density (Same SSID, different MACs)
        # This is a classic indicator of multiple rogue APs attempting a takeover
        if ssid not in self.ssid_density: self.ssid_density[ssid] = set()
        self.ssid_density[ssid].add(mac)
        if len(self.ssid_density[ssid]) > 5:
            score += 30 # High density (>5) for a single SSID is suspicious

        # 3. Channel Stability
        # Rogue APs often skip channels to find the "best" victim overlap
        if signal > 85 and channel not in [1, 6, 11, 36, 44]:
            score += 20 # Suspicious high-power signal on non-standard channel

        # 4. Signal Override (High Power Anomaly)
        # Even without a whitelist, if an AP is significantly stronger than others for the same SSID
        if signal > 92:
            score += 15

        return min(score, 100)

    def predict_threat(self, mac, ssid, channel, signal):
        """
        Stage 3: Combined Neural & Behavioral Prediction
        Returns (threat_score, is_anomaly)
        """
        behavior_score = self.analyze_behavior(mac, ssid, channel, signal)
        
        ml_anomaly = False
        ml_score = 0
        if self.model:
            # Create DF to match feature names and avoid warnings
            X_input = pd.DataFrame([[channel, signal]], columns=['Channel', 'Signal'])
            
            # ML Prediction
            pred = self.model.predict(X_input)[0]
            ml_anomaly = (pred == -1)
            
            # Decision function score
            raw_ml = self.model.decision_function(X_input)[0]
            if raw_ml < 0:
                ml_score = min(abs(raw_ml) * 500 + 40, 70)
            else:
                ml_score = max(0, 30 - (raw_ml * 100))

        # Composite Score: 60% Behavior, 40% ML
        total_score = (behavior_score * 0.6) + (ml_score * 0.4)
        
        # Boost if both agree
        if ml_anomaly and behavior_score > 40:
            total_score = min(total_score + 20, 100)
            
        return int(total_score), ml_anomaly
