"""Safe port scanning and reachability module.

Scans commonly used ports in safe mode with rate limiting,
tests reachability, and ranks ports by stability.
"""

import logging
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Common ports to test
# ---------------------------------------------------------------------------

COMMON_PORTS: list[dict] = [
    {"port": 80, "service": "HTTP", "protocol": "TCP"},
    {"port": 443, "service": "HTTPS", "protocol": "TCP"},
    {"port": 8080, "service": "HTTP Alt", "protocol": "TCP"},
    {"port": 8443, "service": "HTTPS Alt", "protocol": "TCP"},
    {"port": 53, "service": "DNS", "protocol": "TCP/UDP"},
    {"port": 22, "service": "SSH", "protocol": "TCP"},
    {"port": 21, "service": "FTP", "protocol": "TCP"},
    {"port": 25, "service": "SMTP", "protocol": "TCP"},
    {"port": 587, "service": "SMTP TLS", "protocol": "TCP"},
    {"port": 993, "service": "IMAP SSL", "protocol": "TCP"},
    {"port": 995, "service": "POP3 SSL", "protocol": "TCP"},
    {"port": 3389, "service": "RDP", "protocol": "TCP"},
    {"port": 5222, "service": "XMPP", "protocol": "TCP"},
    {"port": 1194, "service": "OpenVPN", "protocol": "TCP/UDP"},
    {"port": 1723, "service": "PPTP", "protocol": "TCP"},
    {"port": 500, "service": "IKE/IPSec", "protocol": "UDP"},
    {"port": 4500, "service": "IPSec NAT-T", "protocol": "UDP"},
    {"port": 51820, "service": "WireGuard", "protocol": "UDP"},
    {"port": 2083, "service": "cPanel SSL", "protocol": "TCP"},
    {"port": 2096, "service": "Webmail SSL", "protocol": "TCP"},
]

# Test target for outbound port checks
DEFAULT_TARGET = "8.8.8.8"


@dataclass
class PortResult:
    """Result of a single port scan."""
    port: int
    service: str
    protocol: str
    reachable: bool
    avg_ms: float
    stability_score: float
    rank: int = 0


class PortScanner:
    """Safe-mode port reachability scanner with rate limiting."""

    TIMEOUT = 3
    SAMPLES = 3

    def __init__(self, restricted_mode: bool = False, max_workers: int = 8):
        self.restricted_mode = restricted_mode
        self.max_workers = max_workers

    def scan_all(self, target: str = DEFAULT_TARGET,
                 ports: list[dict] | None = None) -> list[dict]:
        """Scan all ports against target and return ranked results."""
        port_list = ports or COMMON_PORTS
        results: list[PortResult] = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {
                pool.submit(self._scan_port, target, p): p for p in port_list
            }
            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except Exception as exc:
                    p = futures[future]
                    logger.warning("Port scan failed for %s: %s", p["port"], exc)

        results.sort(key=lambda r: (not r.reachable, r.avg_ms))
        for idx, r in enumerate(results, 1):
            r.rank = idx

        return [self._to_dict(r) for r in results]

    def scan_single(self, target: str, port: int, service: str = "",
                    protocol: str = "TCP") -> dict:
        """Scan a single port."""
        p = {"port": port, "service": service, "protocol": protocol}
        result = self._scan_port(target, p)
        return self._to_dict(result)

    def get_reachable_ports(self, results: list[dict]) -> list[dict]:
        """Filter to only reachable ports."""
        return [r for r in results if r.get("reachable")]

    # -- internals -----------------------------------------------------------

    def _scan_port(self, target: str, port_info: dict) -> PortResult:
        port = port_info["port"]
        times: list[float] = []
        failures = 0

        for _ in range(self.SAMPLES):
            try:
                start = time.perf_counter()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.TIMEOUT)
                s.connect((target, port))
                elapsed = (time.perf_counter() - start) * 1000
                times.append(elapsed)
                s.close()
            except Exception:
                failures += 1
            if self.restricted_mode:
                time.sleep(0.5)
            else:
                time.sleep(0.1)

        reachable = len(times) > 0
        avg = round(sum(times) / len(times), 2) if times else 9999

        stability = 0.0
        if times and len(times) > 1:
            m = sum(times) / len(times)
            var = sum((t - m) ** 2 for t in times) / len(times)
            cv = (var ** 0.5) / m if m else 1
            stability = round(max(0, min(100, 100 - cv * 100)), 1)

        return PortResult(
            port=port,
            service=port_info.get("service", ""),
            protocol=port_info.get("protocol", "TCP"),
            reachable=reachable,
            avg_ms=avg,
            stability_score=stability,
        )

    @staticmethod
    def _to_dict(r: PortResult) -> dict:
        return {
            "port": r.port,
            "service": r.service,
            "protocol": r.protocol,
            "reachable": r.reachable,
            "avg_ms": r.avg_ms,
            "stability_score": r.stability_score,
            "rank": r.rank,
        }
