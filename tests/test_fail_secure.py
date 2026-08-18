"""
Test suite verifying the core FAIL-SECURE architectural guarantee:
Any component failure, timeout, unhandled exception, or corrupt payload
MUST default to containment/escalation (FAIL-SECURE), never a silent pass.
"""
import pytest
from ndr.ingest.models import UnifiedFlow
from ndr.decision.arbiter import DecisionArbiter, ActionVerdict
from ndr.decision.fail_secure import fail_secure_guard


def test_fail_secure_on_unhandled_exception():
    """Verify that an unhandled exception inside evaluation defaults to BLOCK_AND_ISOLATE."""
    arbiter = DecisionArbiter()

    # Create a flow with corrupt attributes that causes a downstream crash
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

    # Force a component crash by passing a feature dictionary with bad types
    corrupted_features = {"duration": "CANNOT_CONVERT_TO_FLOAT_CRASH"}

    verdict_result = arbiter.evaluate_flow(broken_flow, feature_dict=corrupted_features)

    # FAIL-SECURE ASSERTIONS:
    assert verdict_result.verdict == ActionVerdict.BLOCK_AND_ISOLATE, "Must block on failure!"
    assert verdict_result.fail_secure_triggered is True, "Must flag fail_secure_triggered"
    assert "FAIL-SECURE ACTIVATED" in verdict_result.reasons[0]
    assert verdict_result.src_ip == "192.168.1.50"


def test_fail_secure_guard_decorator():
    """Verify fail_secure_guard decorator on an arbitrary crashing function."""
    @fail_secure_guard
    def crashing_detection_pipeline(flow):
        raise TimeoutError("ML Inference timed out after 500ms")

    flow = UnifiedFlow(
        flow_id="FLOW-TIMEOUT-TEST",
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

    result = crashing_detection_pipeline(flow)

    assert result.verdict == ActionVerdict.BLOCK_AND_ISOLATE
    assert result.fail_secure_triggered is True
    assert "TimeoutError" in result.reasons[0]
