"""
OPNsense Firewall REST API Client for automated containment.
Supports live API calls and mock testing mode.
"""
import os
import logging
import requests
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class OPNsenseClient:
    """Client for interacting with OPNsense Firewall REST API."""

    def __init__(
        self,
        api_host: Optional[str] = None,
        api_key: Optional[str] = None,
        api_secret: Optional[str] = None,
        verify_ssl: bool = False,
        mock_mode: bool = True,
        block_table: str = "ndr_blocked_ips"
    ):
        self.api_host = api_host or os.getenv("OPNSENSE_API_HOST", "https://192.168.1.1")
        self.api_key = api_key or os.getenv("OPNSENSE_API_KEY", "mock_key")
        self.api_secret = api_secret or os.getenv("OPNSENSE_API_SECRET", "mock_secret")
        self.verify_ssl = verify_ssl
        self.mock_mode = mock_mode
        self.block_table = block_table
        self.mock_blocked_ips = set()

    def block_ip(self, ip_address: str, reason: str = "NDR Automated Containment") -> Dict[str, Any]:
        """
        Add an IP address to the firewall block table alias.
        Endpoint: /api/firewall/alias_util/add/<table_name>
        """
        if self.mock_mode:
            self.mock_blocked_ips.add(ip_address)
            logger.info(f"[MOCK OPNsense] Blocked IP {ip_address} in table '{self.block_table}'. Reason: {reason}")
            return {
                "status": "success",
                "action": "block",
                "ip": ip_address,
                "table": self.block_table,
                "mode": "mock",
                "active_blocks": len(self.mock_blocked_ips)
            }

        url = f"{self.api_host.rstrip('/')}/api/firewall/alias_util/add/{self.block_table}"
        try:
            response = requests.post(
                url,
                auth=(self.api_key, self.api_secret),
                json={"address": ip_address},
                verify=self.verify_ssl,
                timeout=3.0
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to block IP {ip_address} on OPNsense: {e}")
            raise

    def unblock_ip(self, ip_address: str) -> Dict[str, Any]:
        """Remove an IP address from the firewall block table alias."""
        if self.mock_mode:
            self.mock_blocked_ips.discard(ip_address)
            logger.info(f"[MOCK OPNsense] Removed IP {ip_address} from table '{self.block_table}'.")
            return {"status": "success", "action": "unblock", "ip": ip_address, "mode": "mock"}

        url = f"{self.api_host.rstrip('/')}/api/firewall/alias_util/delete/{self.block_table}"
        try:
            response = requests.post(
                url,
                auth=(self.api_key, self.api_secret),
                json={"address": ip_address},
                verify=self.verify_ssl,
                timeout=3.0
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to unblock IP {ip_address} on OPNsense: {e}")
            raise
