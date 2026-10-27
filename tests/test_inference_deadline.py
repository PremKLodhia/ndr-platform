"""
The arbiter enforces a per-component inference deadline (default 500 ms): a
classifier or autoencoder that does not answer in time yields the fail-secure
BLOCK_AND_ISOLATE verdict with error_type "Timeout".
"""
import threading
import time

import pytest

from ndr.decision import arbiter as arbiter_module
from ndr.decision.arbiter import ActionVerdict, DecisionArbiter
from ndr.ingest.models import UnifiedFlow

BENIGN = {
    "predicted_class": "BENIGN",
    "confidence": 0.99,
    "is_malicious": False,
    "mitre_id": None,
    "mitre_tactic": None,
    "all_probabilities": {"BENIGN": 0.99},
}
NOT_ANOMALOUS = {
    "anomaly_score": 0.01,
    "threshold": 0.5,
    "is_anomalous": False,
    "mitre_id": None,
    "mitre_tactic": None,
}


class SlowClassifier:
    """Blocks until released, like a hung model."""

    def __init__(self, release: threading.Event):
        self.release = release

    def predict_flow(self, feature_dict):
        self.release.wait(timeout=10)
        return BENIGN


class FastClassifier:
    def predict_flow(self, feature_dict):
        return BENIGN


class SlowAutoencoder:
    def __init__(self, release: threading.Event):
        self.release = release

    def evaluate_flow(self, vec):
        self.release.wait(timeout=10)
        return NOT_ANOMALOUS


class FastAutoencoder:
    def evaluate_flow(self, vec):
        return NOT_ANOMALOUS


@pytest.fixture
def release():
    event = threading.Event()
    yield event
    event.set()  # let any blocked worker finish


def flow(flow_id="DEADLINE-001"):
    return UnifiedFlow(
        flow_id=flow_id, timestamp=1700000000.0, src_ip="10.0.0.5", src_port=50000,
        dst_ip="10.0.0.9", dst_port=443, proto="tcp", duration=1.0, src_bytes=1500,
        dst_bytes=9000, src_pkts=10, dst_pkts=12,
    )


def test_default_deadline_is_500ms():
    assert arbiter_module.DEFAULT_COMPONENT_TIMEOUT_MS == 500
    assert DecisionArbiter(classifier=FastClassifier(), autoencoder=FastAutoencoder()).component_timeout_ms == 500


def test_slow_classifier_times_out_fail_secure(release):
    arbiter = DecisionArbiter(classifier=SlowClassifier(release), autoencoder=FastAutoencoder())

    start = time.perf_counter()
    result = arbiter.evaluate_flow(flow())
    elapsed = time.perf_counter() - start

    assert result.verdict == ActionVerdict.BLOCK_AND_ISOLATE
    assert result.fail_secure_triggered is True
    assert result.details["error_type"] == "Timeout"
    assert result.src_ip == "10.0.0.5"
    assert 0.45 <= elapsed < 2.0, f"verdict should arrive at the deadline, took {elapsed:.3f}s"


def test_slow_autoencoder_times_out_fail_secure(release):
    arbiter = DecisionArbiter(classifier=FastClassifier(), autoencoder=SlowAutoencoder(release))

    result = arbiter.evaluate_flow(flow("DEADLINE-002"))

    assert result.verdict == ActionVerdict.BLOCK_AND_ISOLATE
    assert result.fail_secure_triggered is True
    assert result.details["error_type"] == "Timeout"


def test_deadline_is_configurable(release):
    arbiter = DecisionArbiter(classifier=SlowClassifier(release), autoencoder=FastAutoencoder(),
                              component_timeout_ms=50)

    start = time.perf_counter()
    result = arbiter.evaluate_flow(flow("DEADLINE-003"))

    assert result.details["error_type"] == "Timeout"
    assert time.perf_counter() - start < 0.45


def test_fast_components_are_unaffected():
    arbiter = DecisionArbiter(classifier=FastClassifier(), autoencoder=FastAutoencoder())

    result = arbiter.evaluate_flow(flow("DEADLINE-004"))

    assert result.verdict == ActionVerdict.PASS
    assert result.fail_secure_triggered is False


def test_real_models_meet_the_deadline_on_a_normal_flow():
    result = DecisionArbiter().evaluate_flow(flow("DEADLINE-005"))

    assert result.fail_secure_triggered is False
    assert result.details.get("error_type") != "Timeout"


def test_component_errors_keep_their_own_type():
    class Crashing:
        def predict_flow(self, feature_dict):
            raise TimeoutError("raised by the model itself, not a missed deadline")

    result = DecisionArbiter(classifier=Crashing(), autoencoder=FastAutoencoder()).evaluate_flow(flow("DEADLINE-006"))

    assert result.fail_secure_triggered is True
    assert result.details["error_type"] == "TimeoutError"
