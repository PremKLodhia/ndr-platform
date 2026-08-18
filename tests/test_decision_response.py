"""
Unit tests for Decision Arbiter, ContainmentManager dual-backend fail-secure fallback, and SIEM Dispatcher.
"""
import pytest
from unittest.mock import patch, MagicMock
from ndr.ingest.models import UnifiedFlow, SuricataAlert
from ndr.decision.arbiter import DecisionArbiter, ActionVerdict
from ndr.response.opnsense_client import ContainmentManager
from ndr.response.siem_dispatcher import SIEMDispatcher


def test_arbiter_signature_block():
    arbiter = DecisionArbiter()
    critical_alert = SuricataAlert(
        timestamp="2026-08-18T12:00:00Z",
        src_ip="192.168.1.99",
        src_port=54321,
        dst_ip="10.0.0.1",
        dst_port=80,
        proto="tcp",
        signature_id=2010001,
        signature="ET EXPLOIT Apache Struts RCE",
        category="Exploit",
        severity=1
    )
    flow = UnifiedFlow(
        flow_id="EXPLOIT-FLOW-01",
        timestamp=1700000000.0,
        src_ip="192.168.1.99",
        src_port=54321,
        dst_ip="10.0.0.1",
        dst_port=80,
        proto="tcp",
        duration=1.0,
        src_bytes=1000,
        dst_bytes=2000,
        src_pkts=10,
        dst_pkts=10,
        alerts=[critical_alert]
    )

    result = arbiter.evaluate_flow(flow)
    assert result.verdict == ActionVerdict.BLOCK_AND_ISOLATE
    assert "T1190" in result.mitre_ids
    assert result.src_ip == "192.168.1.99"


def test_containment_mock_backend():
    mgr = ContainmentManager(backend="mock")
    log = mgr.block_ip("192.168.1.99", reason="Test RCE Block")
    assert log.status == "SUCCESS"
    assert log.target_ip == "192.168.1.99"
    assert "192.168.1.99" in mgr.mock_blocked_ips

    unblock = mgr.unblock_ip("192.168.1.99")
    assert unblock["status"] == "success"
    assert "192.168.1.99" not in mgr.mock_blocked_ips


def test_containment_fail_secure_fallback_to_iptables():
    """Simulate OPNsense API network failure -> verify automatic fallback to local iptables."""
    mgr = ContainmentManager(backend="opnsense", api_host="https://unreachable.firewall.local")
    
    with patch("requests.post", side_effect=ConnectionError("Firewall gateway unreachable")):
        log = mgr.block_ip("10.10.10.66", reason="Critical C2 Exfiltration")
        assert log.fallback_triggered is True
        assert log.target_ip == "10.10.10.66"
        assert log.backend_used == "iptables"


def test_siem_dispatcher_event_formatting():
    arbiter = DecisionArbiter()
    flow = UnifiedFlow(
        flow_id="FLOW-ECS-01",
        timestamp=1700000000.0,
        src_ip="10.10.10.50",
        src_port=1234,
        dst_ip="172.16.0.1",
        dst_port=8080,
        proto="tcp",
        duration=2.0,
        src_bytes=500,
        dst_bytes=1000,
        src_pkts=5,
        dst_pkts=5
    )
    result = arbiter.evaluate_flow(flow)
    ecs_json = SIEMDispatcher.emit_event(result)
    assert "@timestamp" in ecs_json
    assert "10.10.10.50" in ecs_json
    assert "MITRE ATT&CK" in ecs_json
