"""
Supervised Flow Classifier utilizing Gradient Boosted Trees (XGBoost / LightGBM / sklearn).
Provides multi-class threat classification with MITRE ATT&CK mapping and continuous label encoding.
"""
import os
import json
import logging
import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Tuple, Any
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import HistGradientBoostingClassifier
from ...features.flow_extractor import FLOW_FEATURE_COLUMNS

logger = logging.getLogger(__name__)

THREAT_CLASSES = [
    "BENIGN",
    "PORT_SCAN",
    "DDOS_FLOOD",
    "C2_BEACONING",
    "DNS_TUNNELING",
    "BRUTE_FORCE",
    "EXPLOIT_RCE",
    "RECON_SCAN"
]

CLASS_MITRE_MAP = {
    "BENIGN": ("N/A", "Benign Baseline"),
    "PORT_SCAN": ("T1046", "Network Service Discovery"),
    "RECON_SCAN": ("T1046", "Network Service Discovery"),
    "DDOS_FLOOD": ("T1498.001", "Direct Network Flood"),
    "C2_BEACONING": ("T1071.001", "Web Protocols C2"),
    "DNS_TUNNELING": ("T1071.004", "DNS Exfiltration / Tunneling"),
    "BRUTE_FORCE": ("T1110.001", "Password Guessing"),
    "EXPLOIT_RCE": ("T1190", "Exploit Public-Facing Application")
}


class FlowClassifier:
    """Supervised Tabular Flow Classifier for Threat Detection."""

    def __init__(self, probability_threshold: float = 0.85):
        self.probability_threshold = probability_threshold
        self.model = None
        self.classes = THREAT_CLASSES
        self.feature_columns = FLOW_FEATURE_COLUMNS
        self.is_trained = False
        self.label_encoder = LabelEncoder()
        self._init_model()

    def _init_model(self):
        try:
            import xgboost as xgb
            self.model = xgb.XGBClassifier(
                n_estimators=100,
                max_depth=6,
                learning_rate=0.1,
                random_state=42,
                eval_metric="logloss"
            )
            self.model_backend = "xgboost"
        except Exception as e:
            logger.info(f"XGBoost unavailable ({e}), using HistGradientBoostingClassifier")
            self.model = HistGradientBoostingClassifier(
                max_iter=100,
                max_depth=6,
                random_state=42
            )
            self.model_backend = "sklearn_hgb"

    def fit(self, X: pd.DataFrame, y: np.ndarray) -> "FlowClassifier":
        """Train classifier on extracted features and labels."""
        y_str = np.array([str(item) for item in y])
        
        # Fit label encoder on unique classes present in y
        y_encoded = self.label_encoder.fit_transform(y_str)
        self.fitted_classes_ = list(self.label_encoder.classes_)

        X_clean = X[self.feature_columns].fillna(0.0).values
        self.model.fit(X_clean, y_encoded)
        self.is_trained = True
        return self

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        """Return multi-class probabilities for input feature dataframe."""
        if not self.is_trained:
            n_samples = len(X)
            probs = np.zeros((n_samples, len(self.classes)))
            probs[:, 0] = 1.0
            return probs

        X_clean = X[self.feature_columns].fillna(0.0).values
        raw_probs = self.model.predict_proba(X_clean)
        
        # Handle binary classification output shape from some models
        if len(raw_probs.shape) == 1:
            raw_probs = np.vstack([1 - raw_probs, raw_probs]).T

        n_samples = len(X)
        full_probs = np.zeros((n_samples, len(self.classes)))

        for i, cls_name in enumerate(self.fitted_classes_):
            if cls_name in self.classes:
                target_idx = self.classes.index(cls_name)
                full_probs[:, target_idx] = raw_probs[:, i]

        return full_probs

    def predict_flow(self, feature_dict: Dict[str, float]) -> Dict[str, Any]:
        """Classify a single flow dictionary."""
        df = pd.DataFrame([feature_dict])
        for col in self.feature_columns:
            if col not in df.columns:
                df[col] = 0.0

        probs = self.predict_proba(df)[0]
        top_idx = int(np.argmax(probs))
        top_class = self.classes[top_idx]
        top_prob = float(probs[top_idx])

        is_malicious = top_class != "BENIGN" and top_prob >= self.probability_threshold
        mitre_id, mitre_name = CLASS_MITRE_MAP.get(top_class, ("T1071", "Unknown"))

        return {
            "predicted_class": top_class,
            "confidence": round(top_prob, 4),
            "is_malicious": is_malicious,
            "mitre_id": mitre_id if is_malicious else None,
            "mitre_tactic": mitre_name if is_malicious else None,
            "all_probabilities": {cls_name: round(float(p), 4) for cls_name, p in zip(self.classes, probs)}
        }
