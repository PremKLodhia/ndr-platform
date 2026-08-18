"""
SIEM & Wazuh Dispatcher emitting Elastic Common Schema (ECS) formatted alert logs.
"""
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from ..decision.arbiter import DecisionResult

logger = logging.getLogger(__name__)


class SIEMDispatcher:
    """Formats and dispatches NDR events to Wazuh and SIEM collectors."""

    @staticmethod
    def format_ecs_event(result: DecisionResult) -> Dict[str, Any]:
        """Format DecisionResult into standard Elastic Common Schema (ECS) JSON."""
        event = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "event": {
                "kind": "alert",
                "category": ["network", "intrusion_detection"],
                "type": ["denied" if "BLOCK" in result.verdict.value else "info"],
                "outcome": "success",
                "action": result.verdict.value,
                "reason": " | ".join(result.reasons)
            },
            "source": {
                "ip": result.src_ip
            },
            "destination": {
                "ip": result.dst_ip
            },
            "threat": {
                "framework": "MITRE ATT&CK",
                "technique": {
                    "id": result.mitre_ids,
                }
            },
            "ndr": {
                "flow_id": result.flow_id,
                "confidence": result.confidence,
                "fail_secure": result.fail_secure_triggered,
                "details": result.details
            }
        }
        return event

    @classmethod
    def emit_event(cls, result: DecisionResult) -> str:
        """Emit JSON alert string."""
        event = cls.format_ecs_event(result)
        json_str = json.dumps(event)
        logger.info(f"[SIEM EVENT] {json_str}")
        return json_str
