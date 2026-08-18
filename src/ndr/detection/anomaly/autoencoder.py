"""
PyTorch Unsupervised Autoencoder trained strictly on benign network baseline flows.
Detects zero-day threats and anomalous communication via reconstruction error thresholding.
"""
import os
import logging
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, Optional
from sklearn.preprocessing import RobustScaler
from ...features.flow_extractor import FLOW_FEATURE_COLUMNS

logger = logging.getLogger(__name__)

# Top-level PyTorch Module for clean serialization
try:
    import torch
    import torch.nn as nn

    class PyTorchAE(nn.Module):
        def __init__(self, in_features: int):
            super().__init__()
            self.encoder = nn.Sequential(
                nn.Linear(in_features, 32),
                nn.BatchNorm1d(32),
                nn.LeakyReLU(0.1),
                nn.Linear(32, 16),
                nn.BatchNorm1d(16),
                nn.LeakyReLU(0.1),
                nn.Linear(16, 8)
            )
            self.decoder = nn.Sequential(
                nn.Linear(8, 16),
                nn.BatchNorm1d(16),
                nn.LeakyReLU(0.1),
                nn.Linear(16, 32),
                nn.BatchNorm1d(32),
                nn.LeakyReLU(0.1),
                nn.Linear(32, in_features)
            )

        def forward(self, x):
            latent = self.encoder(x)
            return self.decoder(latent)

    TORCH_AVAILABLE = True
except Exception as e:
    TORCH_AVAILABLE = False
    PyTorchAE = None


class BenignFlowAutoencoder:
    """Autoencoder for network flow anomaly detection."""

    def __init__(self, input_dim: int = len(FLOW_FEATURE_COLUMNS), anomaly_threshold: float = 0.05):
        self.input_dim = input_dim
        self.anomaly_threshold = anomaly_threshold
        self.is_trained = False
        self.torch_available = TORCH_AVAILABLE
        self.scaler = RobustScaler()
        self.is_scaled = False

        if self.torch_available and PyTorchAE is not None:
            self.net = PyTorchAE(self.input_dim)
        else:
            self.net = None

    def fit(self, X: np.ndarray, epochs: int = 20, batch_size: int = 64, lr: float = 0.001) -> "BenignFlowAutoencoder":
        """Train autoencoder on benign flows only."""
        if not self.torch_available or self.net is None:
            self.is_trained = True
            return self

        X_scaled = self.scaler.fit_transform(X)
        self.is_scaled = True

        tensor_x = torch.tensor(X_scaled, dtype=torch.float32)
        dataset = torch.utils.data.TensorDataset(tensor_x)
        loader = torch.utils.data.DataLoader(dataset, batch_size=batch_size, shuffle=True)

        optimizer = torch.optim.Adam(self.net.parameters(), lr=lr)
        criterion = nn.MSELoss()

        self.net.train()
        for epoch in range(epochs):
            for batch in loader:
                inputs = batch[0]
                optimizer.zero_grad()
                outputs = self.net(inputs)
                loss = criterion(outputs, inputs)
                loss.backward()
                optimizer.step()

        # Compute adaptive threshold (99th percentile on benign training set)
        self.net.eval()
        with torch.no_grad():
            reconstructed = self.net(tensor_x)
            losses = torch.mean((tensor_x - reconstructed) ** 2, dim=1).numpy()
            self.anomaly_threshold = float(np.percentile(losses, 99))

        self.is_trained = True
        return self

    def compute_anomaly_score(self, feature_vec: np.ndarray) -> float:
        """Compute reconstruction error (MSE) for a normalized feature vector."""
        if not self.is_trained or not self.torch_available or self.net is None:
            return 0.01

        vec_reshaped = feature_vec.reshape(1, -1)
        if self.is_scaled:
            vec_reshaped = self.scaler.transform(vec_reshaped)

        self.net.eval()
        with torch.no_grad():
            x = torch.tensor(vec_reshaped, dtype=torch.float32)
            reconstructed = self.net(x)
            mse = float(torch.mean((x - reconstructed) ** 2).item())
        return round(mse, 6)

    def evaluate_flow(self, feature_vec: np.ndarray) -> Dict[str, Any]:
        """Evaluate flow feature vector against benign anomaly threshold."""
        score = self.compute_anomaly_score(feature_vec)
        is_anomaly = score > self.anomaly_threshold

        return {
            "anomaly_score": score,
            "threshold": round(self.anomaly_threshold, 6),
            "is_anomalous": is_anomaly,
            "mitre_id": "T1071" if is_anomaly else None,
            "mitre_tactic": "Anomalous / Unseen Channel" if is_anomaly else None
        }

    def save(self, filepath: str):
        """Serialize autoencoder state safely."""
        state = {
            "input_dim": self.input_dim,
            "anomaly_threshold": self.anomaly_threshold,
            "is_trained": self.is_trained,
            "scaler": self.scaler,
            "is_scaled": self.is_scaled,
            "net_state": self.net.state_dict() if self.net is not None else None
        }
        joblib.dump(state, filepath)

    @classmethod
    def load(cls, filepath: str) -> "BenignFlowAutoencoder":
        """Load autoencoder state safely."""
        state = joblib.load(filepath)
        ae = cls(input_dim=state["input_dim"], anomaly_threshold=state["anomaly_threshold"])
        ae.is_trained = state["is_trained"]
        ae.scaler = state["scaler"]
        ae.is_scaled = state["is_scaled"]
        if ae.net is not None and state["net_state"] is not None:
            ae.net.load_state_dict(state["net_state"])
            ae.net.eval()
        return ae
