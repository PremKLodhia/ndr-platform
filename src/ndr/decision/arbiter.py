"""
Decision Arbiter fusing fast signature alerts, supervised classification, and autoencoder anomalies.
"""
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
from ..ingest.models import UnifiedFlow
from ..detection.signatures.suricata_engine import SignatureDetection, SuricataEngine
from ..detection.classifier.xgb_classifier import FlowClassifier
from ..detection.anomaly.autoencoder import BenignFlowAutoencoder
from ..features.flow_extractor import FlowFeatureExtractor
from .fail_secure import FailSecureException, fail_secure_guard

logger = logging.getLogger(__name__)


class ActionVerdict(str, Enum):
    PASS = "PASS"
    ALERT_ONLY = "ALERT_ONLY"
    QUARANTINE_VLAN = "QUARANTINE_VLAN"
    BLOCK_AND_ISOLATE = "BLOCK_AND_ISOLATE"


@dataclass
class DecisionResult:
    flow_id: str
    src_ip: str
    dst_ip: str
    verdict: ActionVerdict
    mitre_ids: List[str]
    reasons: List[str]
    confidence: float
    fail_secure_triggered: bool = False
    details: Dict[str, Any] = field(default_factory=dict)


class DecisionArbiter:
    """
    Fuses dual-path detection signals into an actionable response verdict.
    Guarantees FAIL-SECURE behavior on any component error or anomaly.
    """

    def __init__(
        self,
        classifier: Optional[FlowClassifier] = None,
        autoencoder: Optional[BenignFlowAutoencoder] = None,
        classifier_high_threshold: float = 0.85,
        classifier_med_threshold: float = 0.60,
    ):
        self.classifier = classifier or FlowClassifier()
        self.autoencoder = autoencoder or BenignFlowAutoencoder()
        self.classifier_high_threshold = classifier_high_threshold
        self.classifier_med_threshold = classifier_med_threshold

    @fail_secure_guard
    def evaluate_flow(
        self,
        flow: UnifiedFlow,
        feature_dict: Optional[Dict[str, float]] = None
    ) -> DecisionResult:
        """
        Evaluate a single flow through the dual-path decision tree.
        """
        if feature_dict is None:
            feature_dict = FlowFeatureExtractor.extract_from_unified_flow(flow)

        mitre_ids: List[str] = []
        reasons: List[str] = []
        verdict = ActionVerdict.PASS
        highest_confidence = 0.0

        # --- PATH 1: SIGNATURE EVALUATION ---
        signature_detections: List[SignatureDetection] = []
        for alert in flow.alerts:
            sig_det = SuricataEngine.evaluate_alert(alert)
            signature_detections.append(sig_det)
            if sig_det.mitre_id:
                mitre_ids.append(sig_det.mitre_id)
            reasons.append(f"Signature Match: {sig_det.alert.signature} (Sev: {sig_det.alert.severity})")

            if sig_det.alert.severity == 1:
                verdict = ActionVerdict.BLOCK_AND_ISOLATE
                highest_confidence = max(highest_confidence, 0.99)
            elif sig_det.alert.severity == 2 and verdict != ActionVerdict.BLOCK_AND_ISOLATE:
                verdict = ActionVerdict.QUARANTINE_VLAN
                highest_confidence = max(highest_confidence, 0.80)

        # --- PATH 2: SUPERVISED CLASSIFIER ---
        cls_result = self.classifier.predict_flow(feature_dict)
        cls_conf = cls_result["confidence"]
        predicted_class = cls_result["predicted_class"]

        if cls_result["is_malicious"]:
            if cls_result["mitre_id"]:
                mitre_ids.append(cls_result["mitre_id"])
            reasons.append(f"ML Classifier: {predicted_class} ({cls_conf*100:.1f}%)")
            highest_confidence = max(highest_confidence, cls_conf)

            if cls_conf >= self.classifier_high_threshold:
                verdict = ActionVerdict.BLOCK_AND_ISOLATE
            elif cls_conf >= self.classifier_med_threshold and verdict == ActionVerdict.PASS:
                verdict = ActionVerdict.QUARANTINE_VLAN

        # --- PATH 3: UNSUPERVISED ANOMALY AUTOENCODER ---
        import numpy as np
        vec = np.array(list(feature_dict.values()), dtype=np.float32)
        ae_result = self.autoencoder.evaluate_flow(vec)

        if ae_result["is_anomalous"]:
            if ae_result["mitre_id"]:
                mitre_ids.append(ae_result["mitre_id"])
            reasons.append(f"Autoencoder Anomaly: Loss {ae_result['anomaly_score']:.4f} > Thresh {ae_result['threshold']:.4f}")
            if verdict == ActionVerdict.PASS:
                verdict = ActionVerdict.QUARANTINE_VLAN
                highest_confidence = max(highest_confidence, 0.75)

        # Default confidence for benign
        if verdict == ActionVerdict.PASS:
            highest_confidence = round(1.0 - max(cls_conf if predicted_class != "BENIGN" else 0.0, 0.0), 4)

        return DecisionResult(
            flow_id=flow.flow_id,
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            verdict=verdict,
            mitre_ids=list(set(mitre_ids)),
            reasons=reasons,
            confidence=round(highest_confidence, 4),
            fail_secure_triggered=False,
            details={
                "classifier": cls_result,
                "anomaly": ae_result,
                "signature_count": len(signature_detections)
            }
        )
