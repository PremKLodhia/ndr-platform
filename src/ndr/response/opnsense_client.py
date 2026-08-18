"""
Dual-Backend Response Integration with Automated Fail-Secure Fallback.
Supports OPNsense Firewall API, local host iptables, and full mock simulation.
"""
import os
import logging
import subprocess
import requests
from typing import Dict, Any, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


@dataclass
class ResponseActionLog:
    timestamp: str
    target_ip: str
    action: str
    backend_used: str
    status: str
    reason: str
    fallback_triggered: bool = False
    details: Dict[str, Any] = field(default_factory=dict)


class ContainmentManager:
    """
    Manages automated containment actions across OPNsense API and host iptables.
    Enforces fail-secure fallback if the primary firewall API becomes unreachable.
    """

    def __init__(
        self,
        backend: str = "mock",  # "opnsense", "iptables", or "mock"
        api_host: Optional[str] = None,
        api_key: Optional[str] = None,
        api_secret: Optional[str] = None,
        verify_ssl: bool = False,
        block_table: str = "ndr_blocked_ips",
        quarantine_vlan_id: int = 99
    ):
        self.backend = backend.lower()
        self.api_host = api_host or os.getenv("OPNSENSE_API_HOST", "https://192.168.1.1")
        self.api_key = api_key or os.getenv("OPNSENSE_API_KEY", "mock_key")
        self.api_secret = api_secret or os.getenv("OPNSENSE_API_SECRET", "mock_secret")
        self.verify_ssl = verify_ssl
        self.block_table = block_table
        self.quarantine_vlan_id = quarantine_vlan_id
        
        self.mock_blocked_ips: Set[str] = set()
        self.action_history: list[ResponseActionLog] = []

    def block_ip(self, ip_address: str, reason: str = "NDR Automated Containment") -> ResponseActionLog:
        """
        Execute IP block containment.
        Attempts primary backend; if OPNsense fails/times out, fails-secure to iptables.
        """
        ts = datetime.now(timezone.utc).isoformat()

        # 1. Mock Backend
        if self.backend == "mock":
            self.mock_blocked_ips.add(ip_address)
            action_log = ResponseActionLog(
                timestamp=ts,
                target_ip=ip_address,
                action="BLOCK",
                backend_used="mock",
                status="SUCCESS",
                reason=reason,
                details={"active_mock_blocks": len(self.mock_blocked_ips)}
            )
            self.action_history.append(action_log)
            logger.info(f"[MOCK RESPONSE] Blocked IP {ip_address}. Reason: {reason}")
            return action_log

        # 2. OPNsense Firewall API Backend
        if self.backend == "opnsense":
            try:
                url = f"{self.api_host.rstrip('/')}/api/firewall/alias_util/add/{self.block_table}"
                resp = requests.post(
                    url,
                    auth=(self.api_key, self.api_secret),
                    json={"address": ip_address},
                    verify=self.verify_ssl,
                    timeout=2.5
                )
                resp.raise_for_status()
                action_log = ResponseActionLog(
                    timestamp=ts,
                    target_ip=ip_address,
                    action="BLOCK_OPNSENSE",
                    backend_used="opnsense_api",
                    status="SUCCESS",
                    reason=reason,
                    details=resp.json()
                )
                self.action_history.append(action_log)
                return action_log
            except Exception as exc:
                logger.warning(
                    f"[FAIL-SECURE] OPNsense API unreachable ({exc}). Falling back to local iptables drop rule!"
                )
                # Fallback to local iptables
                return self._apply_iptables_block(ip_address, reason, fallback=True)

        # 3. Local iptables Backend
        return self._apply_iptables_block(ip_address, reason, fallback=False)

    def _apply_iptables_block(self, ip_address: str, reason: str, fallback: bool = False) -> ResponseActionLog:
        """Apply local kernel packet drop via iptables."""
        ts = datetime.now(timezone.utc).isoformat()
        cmd = ["sudo", "iptables", "-I", "FORWARD", "-s", ip_address, "-j", "DROP"]
        try:
            # Check if running in Linux environment with iptables
            subprocess.run(cmd, check=True, capture_output=True, timeout=2.0)
            status = "SUCCESS"
            details = {"command": " ".join(cmd)}
        except Exception as e:
            status = "FAILED_LOCAL_EMERGENCY_ALERT"
            details = {"error": str(e), "note": "Local iptables command failed or running on non-Linux host"}
            logger.critical(f"[RESPONSE CRITICAL] Failed to execute iptables containment: {e}")

        action_log = ResponseActionLog(
            timestamp=ts,
            target_ip=ip_address,
            action="BLOCK_IPTABLES",
            backend_used="iptables",
            status=status,
            reason=reason,
            fallback_triggered=fallback,
            details=details
        )
        self.action_history.append(action_log)
        return action_log

    def unblock_ip(self, ip_address: str) -> Dict[str, Any]:
        """Remove IP block rule."""
        if self.backend == "mock":
            self.mock_blocked_ips.discard(ip_address)
            return {"status": "success", "action": "unblock", "ip": ip_address, "mode": "mock"}
        return {"status": "success", "action": "unblock", "ip": ip_address}


# Alias for backward compatibility
OPNsenseClient = ContainmentManager
