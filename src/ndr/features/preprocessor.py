"""
Feature scaling, normalization, and validation pipeline.
"""
import numpy as np
import pandas as pd
from typing import Optional, List, Tuple
from sklearn.preprocessing import RobustScaler, StandardScaler
from .flow_extractor import FLOW_FEATURE_COLUMNS


class FeaturePreprocessor:
    """Scales and validates feature vectors before model inference or training."""

    def __init__(self, scaler_type: str = "robust"):
        self.scaler = RobustScaler() if scaler_type == "robust" else StandardScaler()
        self.is_fitted = False
        self.feature_names = FLOW_FEATURE_COLUMNS

    def fit(self, X: pd.DataFrame) -> "FeaturePreprocessor":
        """Fit scaler on training data."""
        X_clean = self._clean_dataframe(X)
        self.scaler.fit(X_clean[self.feature_names])
        self.is_fitted = True
        return self

    def transform(self, X: pd.DataFrame) -> np.ndarray:
        """Scale features to standardized numerical array."""
        if not self.is_fitted:
            raise RuntimeError("Preprocessor must be fitted before transforming.")
        X_clean = self._clean_dataframe(X)
        return self.scaler.transform(X_clean[self.feature_names])

    def fit_transform(self, X: pd.DataFrame) -> np.ndarray:
        """Fit and transform."""
        return self.fit(X).transform(X)

    def _clean_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """Clean infs and NaNs defensively."""
        df_copy = df.copy()
        for col in self.feature_names:
            if col not in df_copy.columns:
                df_copy[col] = 0.0
        df_copy = df_copy.replace([np.inf, -np.inf], np.nan)
        df_copy = df_copy.fillna(0.0)
        return df_copy
