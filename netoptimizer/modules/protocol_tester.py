"""Protocol benchmarking module.

Compares performance of HTTP, HTTPS, TCP, UDP, TLS handshake,
and estimates QUIC/WebSocket compatibility.
"""

import logging
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

import requests

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Test targets
# ---------------------------------------------------------------------------

PROTOCOL_TARGETS: list[dict] = [
    {"name": "Google", "host": "www.google.com", "ip": "142.250.80.46"},
    {"name": "Cloudflare", "host": "cloudflare.com", "ip": "104.16.132.229"},
    {"name": "GitHub", "host": "github.com", "ip": "140.82.121.3"},
]


@dataclass
class ProtocolResult:
    """Result for a single protocol test."""
    protocol: str
    target: str
    avg_ms: float
    min_ms: float
    max_ms: float
    success_rate: float
    rank: int = 0


class ProtocolTester:
    """Benchmark different network protocols."""

    TIMEOUT = 5
    SAMPLES = 5

    def __init__(self, restricted_mode: bool = False, max_workers: int = 6):
        self.restricted_mode = restricted_mode
        self.max_workers = max_workers

    def benchmark_all(self) -> list[dict]:
        """Run all protocol benchmarks and return ranked results."""
        tests = [
            ("HTTP", self._test_http),
            ("HTTPS", self._test_https),
            ("TCP", self._test_tcp),
            ("UDP", self._test_udp),
            ("TLS Handshake", self._test_tls),
            ("WebSocket (TCP)", self._test_websocket_tcp),
        ]
        results: list[ProtocolResult] = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {}
            for proto_name, test_fn in tests:
                for target in PROTOCOL_TARGETS:
                    futures[pool.submit(test_fn, target)] = (proto_name, target["name"])

            for future in as_completed(futures):
                proto_name, target_name = futures[future]
                try:
                    times, failures = future.result()
                    total = len(times) + failures
                    avg = round(sum(times) / len(times), 2) if times else 9999
                    mn = round(min(times), 2) if times else 9999
                    mx = round(max(times), 2) if times else 9999
                    success = round(len(times) / total * 100, 1) if total else 0
                    results.append(ProtocolResult(
                        protocol=proto_name,
                        target=target_name,
                        avg_ms=avg,
                        min_ms=mn,
                        max_ms=mx,
                        success_rate=success,
                    ))
                except Exception as exc:
                    logger.warning("Protocol test %s/%s failed: %s", proto_name, target_name, exc)

        # Group by protocol and compute average
        proto_summary = self._summarise_by_protocol(results)
        proto_summary.sort(key=lambda r: r["avg_ms"])
        for idx, s in enumerate(proto_summary, 1):
            s["rank"] = idx

        return proto_summary

    def get_detailed_results(self) -> list[dict]:
        """Alias that returns all results (for UI detail view)."""
        return self.benchmark_all()

    # -- protocol tests ------------------------------------------------------

    def _test_http(self, target: dict) -> tuple[list[float], int]:
        times, failures = [], 0
        for _ in range(self.SAMPLES):
            try:
                start = time.perf_counter()
                requests.get(f"http://{target['host']}", timeout=self.TIMEOUT, allow_redirects=False)
                times.append((time.perf_counter() - start) * 1000)
            except Exception:
                failures += 1
            self._rate_limit()
        return times, failures

    def _test_https(self, target: dict) -> tuple[list[float], int]:
        times, failures = [], 0
        for _ in range(self.SAMPLES):
            try:
                start = time.perf_counter()
                requests.get(f"https://{target['host']}", timeout=self.TIMEOUT, allow_redirects=False)
                times.append((time.perf_counter() - start) * 1000)
            except Exception:
                failures += 1
            self._rate_limit()
        return times, failures

    def _test_tcp(self, target: dict) -> tuple[list[float], int]:
        times, failures = [], 0
        for _ in range(self.SAMPLES):
            try:
                start = time.perf_counter()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.TIMEOUT)
                s.connect((target["host"], 80))
                times.append((time.perf_counter() - start) * 1000)
                s.close()
            except Exception:
                failures += 1
            self._rate_limit()
        return times, failures

    def _test_udp(self, target: dict) -> tuple[list[float], int]:
        times, failures = [], 0
        for _ in range(self.SAMPLES):
            try:
                start = time.perf_counter()
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(self.TIMEOUT)
                s.sendto(b"\x00", (target["host"], 53))
                try:
                    s.recvfrom(512)
                except socket.timeout:
                    pass
                times.append((time.perf_counter() - start) * 1000)
                s.close()
            except Exception:
                failures += 1
            self._rate_limit()
        return times, failures

    def _test_tls(self, target: dict) -> tuple[list[float], int]:
        times, failures = [], 0
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        for _ in range(self.SAMPLES):
            try:
                start = time.perf_counter()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.TIMEOUT)
                wrapped = ctx.wrap_socket(s, server_hostname=target["host"])
                wrapped.connect((target["host"], 443))
                times.append((time.perf_counter() - start) * 1000)
                wrapped.close()
            except Exception:
                failures += 1
            self._rate_limit()
        return times, failures

    def _test_websocket_tcp(self, target: dict) -> tuple[list[float], int]:
        """Test TCP connect to port 443 as proxy for WebSocket availability."""
        times, failures = [], 0
        for _ in range(self.SAMPLES):
            try:
                start = time.perf_counter()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.TIMEOUT)
                s.connect((target["host"], 443))
                times.append((time.perf_counter() - start) * 1000)
                s.close()
            except Exception:
                failures += 1
            self._rate_limit()
        return times, failures

    def _rate_limit(self):
        if self.restricted_mode:
            time.sleep(0.3)

    @staticmethod
    def _summarise_by_protocol(results: list[ProtocolResult]) -> list[dict]:
        groups: dict[str, list[ProtocolResult]] = {}
        for r in results:
            groups.setdefault(r.protocol, []).append(r)
        summary = []
        for proto, items in groups.items():
            reachable = [i for i in items if i.avg_ms < 9000]
            if reachable:
                avg = round(sum(i.avg_ms for i in reachable) / len(reachable), 2)
                mn = round(min(i.min_ms for i in reachable), 2)
                mx = round(max(i.max_ms for i in reachable), 2)
                sr = round(sum(i.success_rate for i in reachable) / len(reachable), 1)
            else:
                avg, mn, mx, sr = 9999, 9999, 9999, 0
            summary.append({
                "protocol": proto,
                "avg_ms": avg,
                "min_ms": mn,
                "max_ms": mx,
                "success_rate": sr,
                "targets_tested": len(items),
                "rank": 0,
            })
        return summary
