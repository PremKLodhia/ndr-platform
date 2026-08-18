"""
Model Training Pipeline for Phase 2:
- Trains XGBoost/LightGBM multi-class flow classifier on 80/20 stratified split with early stopping.
- Tunes decision threshold favoring precision over recall (precision-first posture).
- Serializes trained model and feature importances to models/.
- Trains PyTorch Autoencoder exclusively on benign flows with 99th-percentile reconstruction threshold.
"""
import os
import json
import logging
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

from ndr.features.flow_extractor import FLOW_FEATURE_COLUMNS
from ndr.features.preprocessor import FeaturePreprocessor
from ndr.detection.classifier.xgb_classifier import FlowClassifier, THREAT_CLASSES
from ndr.detection.anomaly.autoencoder import BenignFlowAutoencoder

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ModelTrainer")


def train_and_serialize_models(
    data_path: str = "data/processed/processed_flows.csv",
    model_dir: str = "models"
):
    out_models = Path(model_dir)
    out_models.mkdir(parents=True, exist_ok=True)

    if not Path(data_path).exists():
        logger.error(f"Processed dataset not found at {data_path}. Run scripts/build_dataset.py first.")
        return

    logger.info(f"Loading processed dataset from {data_path}...")
    df = pd.read_csv(data_path)
    logger.info(f"Dataset shape: {df.shape}. Class breakdown:\n{df['attack_category'].value_counts()}")

    X = df[FLOW_FEATURE_COLUMNS].fillna(0.0)
    y = df["attack_category"].values

    # 80/20 Stratified Holdout Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    logger.info(f"Train split: {X_train.shape[0]} flows, Test split: {X_test.shape[0]} flows.")

    # 1. Train Supervised Flow Classifier (Precision-Favored Threshold: 0.85)
    logger.info("Training Supervised XGBoost/HistGradientBoosting Flow Classifier...")
    classifier = FlowClassifier(probability_threshold=0.85)
    classifier.fit(X_train, y_train)

    # Calculate and Save Feature Importances
    importances = {}
    if hasattr(classifier.model, "feature_importances_"):
        raw_imp = classifier.model.feature_importances_
        importances = {col: round(float(imp), 6) for col, imp in zip(FLOW_FEATURE_COLUMNS, raw_imp)}
        importances = dict(sorted(importances.items(), key=lambda item: item[1], reverse=True))

    imp_path = out_models / "feature_importances.json"
    imp_path.write_text(json.dumps(importances, indent=2), encoding="utf-8")
    logger.info(f"Saved feature importances to {imp_path}")

    # Serialize Supervised Classifier
    model_save_path = out_models / "flow_classifier.joblib"
    joblib.dump(classifier, model_save_path)
    logger.info(f"Saved supervised classifier to {model_save_path}")

    # 2. Train Unsupervised Anomaly Autoencoder (Benign Flows ONLY)
    logger.info("Training Unsupervised PyTorch Autoencoder on Benign flows...")
    benign_mask_train = y_train == "BENIGN"
    X_train_benign = X_train[benign_mask_train].values.astype(np.float32)

    autoencoder = BenignFlowAutoencoder(input_dim=len(FLOW_FEATURE_COLUMNS))
    autoencoder.fit(X_train_benign, epochs=25, batch_size=32)

    # Serialize Autoencoder
    ae_save_path = out_models / "benign_autoencoder.joblib"
    autoencoder.save(str(ae_save_path))
    logger.info(f"Saved benign autoencoder to {ae_save_path} (Calibrated Threshold: {autoencoder.anomaly_threshold:.6f})")

    logger.info("Model training and serialization completed successfully.")


if __name__ == "__main__":
    train_and_serialize_models()
