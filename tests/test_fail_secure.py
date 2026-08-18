"""
Test suite verifying the core FAIL-SECURE architectural guarantee:
Any component failure, timeout, unhandled exception, or corrupt payload
MUST default to containment/escalation (FAIL-SECURE), never a silent pass.
"""
import pytest
import time
from unittest.mock import MagicMock
from ndr.ingest.models import UnifiedFlow
from ndr.decision.arbiter import DecisionArbiter, ActionVerdict
from ndr.decision.fail_secure import fail_secure_guard, FailSecureException
from ndr.detection.classifier.xgb_classifier import FlowClassifier
from ndr.detection.anomaly.autoencoder import BenignFlowAutoencoder


def test_fail_secure_on_corrupt_feature_payload():
    """Verify that unhandled exceptions during feature processing default to BLOCK_AND_ISOLATE."""
    arbiter = DecisionArbiter()
    broken_flow = UnifiedFlow(
        flow_id="FAIL-SECURE-TEST-001",
        timestamp=1700000000.0,
        src_ip="192.168.1.50",
        src_port=4444,
        dst_ip="10.0.0.1",
        dst_port=80,
        proto="tcp",
        duration=-1.0,
        src_bytes=100,
        dst_bytes=200,
        src_pkts=5,
        dst_pkts=5
    )

    corrupted_features = {"duration": "CANNOT_CONVERT_TO_FLOAT_CRASH"}
    result = arbiter.evaluate_flow(broken_flow, feature_dict=corrupted_features)

    assert result.verdict == ActionVerdict.BLOCK_AND_ISOLATE
    assert result.fail_secure_triggered is True
    assert "FAIL-SECURE ACTIVATED" in result.reasons[0]
    assert result.src_ip == "192.168.1.50"


def test_fail_secure_on_classifier_timeout():
    """Simulate classifier timeout / unresponsiveness -> assert verdict is never PASS."""
    mock_classifier = MagicMock(spec=FlowClassifier)
    mock_classifier.predict_flow.side_effect = TimeoutError("XGBoost inference exceeded 500ms deadline")

    arbiter = DecisionArbiter(classifier=mock_classifier)
    flow = UnifiedFlow(
        flow_id="TIMEOUT-FLOW-002",
        timestamp=1700000000.0,
        src_ip="10.10.10.10",
        src_port=55555,
        dst_ip="1.1.1.1",
        dst_port=53,
        proto="udp",
        duration=1.0,
        src_bytes=50,
        dst_bytes=50,
        src_pkts=1,
        dst_pkts=1
    )

    result = arbiter.evaluate_flow(flow)
    assert result.verdict != ActionVerdict.PASS, "Must never pass on timeout!"
    assert result.verdict == ActionVerdict.BLOCK_AND_ISOLATE
    assert result.fail_secure_triggered is True
    assert "TimeoutError" in result.reasons[0]


def test_fail_secure_on_unreachable_autoencoder():
    """Simulate unhandled failure or crash in anomaly autoencoder -> assert containment."""
    mock_autoencoder = MagicMock(spec=BenignFlowAutoencoder)
    mock_autoencoder.evaluate_flow.side_effect = ConnectionResetError("Autoencoder Torch backend crashed (CUDA OOM)")

    arbiter = DecisionArbiter(autoencoder=mock_autoencoder)
    flow = UnifiedFlow(
        flow_id="CRASH-AE-FLOW-003",
        timestamp=1700000000.0,
        src_ip="172.16.5.99",
        src_port=12345,
        dst_ip="8.8.8.8",
        dst_port=53,
        proto="udp",
        duration=0.1,
        src_bytes=100,
        dst_bytes=100,
        src_pkts=2,
        dst_pkts=2
    )

    result = arbiter.evaluate_flow(flow)
    assert result.verdict != ActionVerdict.PASS
    assert result.verdict == ActionVerdict.BLOCK_AND_ISOLATE
    assert result.fail_secure_triggered is True
    assert "ConnectionResetError" in result.reasons[0]


def test_fail_secure_structured_logging():
    """Verify that fail-secure event produces structured logging details for SIEM."""
    arbiter = DecisionArbiter()
    flow = UnifiedFlow(
        flow_id="LOG-TEST-004",
        timestamp=1700000000.0,
        src_ip="192.168.1.77",
        src_port=8080,
        dst_ip="10.0.0.1",
        dst_port=443,
        proto="tcp",
        duration=1.0,
        src_bytes=10,
        dst_bytes=10,
        src_pkts=1,
        dst_pkts=1
    )

    @fail_secure_guard
    def simulated_failing_component(f):
        raise ValueError("Corrupt memory buffer in packet parser")

    res = simulated_failing_component(flow)
    assert res.fail_secure_triggered is True
    assert res.details["error_type"] == "ValueError"
    assert "Corrupt memory buffer" in res.details["error_message"]
