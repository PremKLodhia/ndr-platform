"""
Fail-Secure Architecture Enforcement:
Guarantees that component timeouts, memory faults, unparseable payloads,
or unhandled exceptions default to defensive containment (BLOCK/QUARANTINE),
NEVER a silent pass.
"""
import functools
import logging
from typing import Callable, Any

logger = logging.getLogger(__name__)


class FailSecureException(Exception):
    """Raised when a pipeline component fails and triggers fail-secure containment."""
    pass


def fail_secure_guard(func: Callable) -> Callable:
    """
    Decorator wrapping decision functions. If any exception occurs during
    feature extraction, model inference, or arbitration, it intercepts the error
    and returns a defensive DecisionResult with verdict BLOCK_AND_ISOLATE.
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs) -> Any:
        try:
            return func(*args, **kwargs)
        except Exception as exc:
            logger.critical(
                f"[FAIL-SECURE TRIGGERED] Error during {func.__name__}: {exc}. "
                "Defaulting to defensive containment (BLOCK_AND_ISOLATE).",
                exc_info=True
            )
            # Import locally to avoid circular dependencies
            from .arbiter import ActionVerdict, DecisionResult
            
            # Extract basic IP if passed in args
            src_ip = "0.0.0.0"
            dst_ip = "0.0.0.0"
            flow_id = "UNKNOWN_ERROR_FLOW"

            if len(args) > 1 and hasattr(args[1], "src_ip"):
                flow = args[1]
                src_ip = getattr(flow, "src_ip", "0.0.0.0")
                dst_ip = getattr(flow, "dst_ip", "0.0.0.0")
                flow_id = getattr(flow, "flow_id", "UNKNOWN_ERROR_FLOW")

            return DecisionResult(
                flow_id=flow_id,
                src_ip=src_ip,
                dst_ip=dst_ip,
                verdict=ActionVerdict.BLOCK_AND_ISOLATE,
                mitre_ids=["T1071"],
                reasons=[f"FAIL-SECURE ACTIVATED: Component Failure ({type(exc).__name__}: {str(exc)})"],
                confidence=1.0,
                fail_secure_triggered=True,
                details={"error_type": type(exc).__name__, "error_message": str(exc)}
            )
    return wrapper
