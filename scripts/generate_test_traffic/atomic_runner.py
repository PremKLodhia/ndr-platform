"""
Atomic Red Team Style Attack Scenario Runner.
Executes parameterizable network technique tests against specified lab target IP/hosts.
"""
import sys
import time
import argparse
import requests
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("AtomicRunner")


def run_atomic_c2_beacon(target_ip: str, port: int = 80, count: int = 10, interval: float = 1.0):
    """Simulate Atomic Test T1071.001 Web C2 beaconing."""
    logger.info(f"Executing Atomic Test T1071.001 (Web C2 Beacon) against {target_ip}:{port}...")
    headers = {"User-Agent": "Mozilla/5.0 (AtomicRedTeam-Simulated-Agent)", "Accept": "*/*"}
    for i in range(count):
        url = f"http://{target_ip}:{port}/heartbeat?agent_id=atomic-test-01&seq={i}"
        try:
            requests.get(url, headers=headers, timeout=1.0)
            logger.info(f"  [>] Sent C2 Heartbeat {i+1}/{count}")
        except Exception:
            # Expected if target port is closed/filtered, traffic is still captured by tap
            logger.info(f"  [>] Emitted C2 Packet {i+1}/{count} -> {url}")
        time.sleep(interval)


def main():
    parser = argparse.ArgumentParser(description="NDR Atomic Attack Simulator")
    parser.add_argument("--technique", choices=["T1071.001", "T1046", "T1071.004"], default="T1071.001")
    parser.add_argument("--target", default="192.168.10.50", help="Target host IP in lab")
    parser.add_argument("--count", type=int, default=10, help="Number of test packets/requests")
    args = parser.parse_args()

    if args.technique == "T1071.001":
        run_atomic_c2_beacon(args.target, count=args.count)
    else:
        logger.info(f"Technique {args.technique} requested.")


if __name__ == "__main__":
    main()
