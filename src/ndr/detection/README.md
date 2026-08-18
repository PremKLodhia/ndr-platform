# Detection Module

Coordinates the dual-path detection pipeline:
- `signatures/`: Suricata alert processing & ATT&CK enrichment
- `classifier/`: Supervised tabular models (XGBoost/LightGBM)
- `anomaly/`: Benign baseline reconstruction autoencoder