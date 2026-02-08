"""DNS analysis and benchmarking module.

Tests public and custom DNS servers, measures response time, reliability,
and error rate. Provides ranking and history support.
"""

import logging
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Well-known public DNS servers
# ---------------------------------------------------------------------------

PUBLIC_DNS_SERVERS: list[dict] = [
    {"name": "Google DNS", "ip": "8.8.8.8", "secondary": "8.8.4.4"},
    {"name": "Cloudflare", "ip": "1.1.1.1", "secondary": "1.0.0.1"},
    {"name": "Quad9", "ip": "9.9.9.9", "secondary": "149.112.112.112"},
    {"name": "OpenDNS", "ip": "208.67.222.222", "secondary": "208.67.220.220"},
    {"name": "AdGuard DNS", "ip": "94.140.14.14", "secondary": "94.140.15.15"},
    {"name": "Comodo DNS", "ip": "8.26.56.26", "secondary": "8.20.247.20"},
    {"name": "CleanBrowsing", "ip": "185.228.168.9", "secondary": "185.228.169.9"},
    {"name": "Level3 DNS", "ip": "4.2.2.1", "secondary": "4.2.2.2"},
    {"name": "Yandex DNS", "ip": "77.88.8.8", "secondary": "77.88.8.1"},
    {"name": "Verisign DNS", "ip": "64.6.64.6", "secondary": "64.6.65.6"},
    {"name": "Shecan DNS", "ip": "178.22.122.100", "secondary": "185.51.200.2"},
    {"name": "403 DNS", "ip": "10.202.10.202", "secondary": "10.202.10.102"},
    {"name": "Electro DNS", "ip": "78.157.42.101", "secondary": "78.157.42.100"},
]

# Domains used for testing
TEST_DOMAINS = [
    "google.com",
    "cloudflare.com",
    "github.com",
    "amazon.com",
    "microsoft.com",
]


@dataclass
class DNSResult:
    """Result of a DNS benchmark for one server."""
    name: str
    ip: str
    avg_ms: float
    min_ms: float
    max_ms: float
    reliability_pct: float
    error_count: int
    total_queries: int
    reachable: bool
    rank: int = 0


class DNSAnalyzer:
    """Benchmark and compare DNS servers."""

    TIMEOUT = 3
    SAMPLES = 5

    def __init__(self, restricted_mode: bool = False, max_workers: int = 8):
        self.restricted_mode = restricted_mode
        self.max_workers = max_workers
        self.history: list[list[dict]] = []

    def benchmark_all(self, servers: list[dict] | None = None) -> list[dict]:
        """Benchmark all DNS servers and return ranked results."""
        servers = servers or PUBLIC_DNS_SERVERS
        results: list[DNSResult] = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {
                pool.submit(self._benchmark_server, srv): srv for srv in servers
            }
            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except Exception as exc:
                    srv = futures[future]
                    logger.warning("DNS benchmark failed for %s: %s", srv["name"], exc)

        results.sort(key=lambda r: (not r.reachable, -r.reliability_pct, r.avg_ms))
        for idx, r in enumerate(results, 1):
            r.rank = idx

        dict_results = [self._to_dict(r) for r in results]
        self.history.append(dict_results)
        return dict_results

    def benchmark_custom(self, name: str, ip: str) -> dict:
        """Benchmark a single custom DNS server."""
        srv = {"name": name, "ip": ip}
        result = self._benchmark_server(srv)
        return self._to_dict(result)

    def get_best_dns(self, results: list[dict], top_n: int = 3) -> list[dict]:
        """Return top N recommended DNS servers."""
        reachable = [r for r in results if r.get("reachable")]
        return reachable[:top_n]

    def get_history(self) -> list[list[dict]]:
        """Return historical benchmark results."""
        return self.history

    # -- internals -----------------------------------------------------------

    def _benchmark_server(self, srv: dict) -> DNSResult:
        """Benchmark a single DNS server."""
        times: list[float] = []
        errors = 0
        total = 0

        for domain in TEST_DOMAINS:
            for _ in range(self.SAMPLES):
                total += 1
                try:
                    start = time.perf_counter()
                    self._dns_query(srv["ip"], domain)
                    elapsed = (time.perf_counter() - start) * 1000
                    times.append(elapsed)
                except Exception:
                    errors += 1
                if self.restricted_mode:
                    time.sleep(0.2)

        reachable = len(times) > 0
        avg = round(sum(times) / len(times), 2) if times else 9999
        mn = round(min(times), 2) if times else 9999
        mx = round(max(times), 2) if times else 9999
        reliability = round((total - errors) / total * 100, 1) if total else 0

        return DNSResult(
            name=srv["name"],
            ip=srv["ip"],
            avg_ms=avg,
            min_ms=mn,
            max_ms=mx,
            reliability_pct=reliability,
            error_count=errors,
            total_queries=total,
            reachable=reachable,
        )

    def _dns_query(self, server_ip: str, domain: str) -> str:
        """Send a raw DNS A-record query and return the resolved IP."""
        # Build DNS query packet
        tx_id = b"\xaa\xbb"
        flags = b"\x01\x00"  # standard query, recursion desired
        counts = struct.pack(">HHHH", 1, 0, 0, 0)
        question = b""
        for part in domain.split("."):
            question += bytes([len(part)]) + part.encode()
        question += b"\x00"
        question += struct.pack(">HH", 1, 1)  # A record, IN class

        packet = tx_id + flags + counts + question

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.TIMEOUT)
        try:
            sock.sendto(packet, (server_ip, 53))
            data, _ = sock.recvfrom(512)
            # Parse minimal answer
            if len(data) > 12:
                return server_ip  # simplified – we only care about timing
            return ""
        finally:
            sock.close()

    @staticmethod
    def _to_dict(r: DNSResult) -> dict:
        return {
            "name": r.name,
            "ip": r.ip,
            "avg_ms": r.avg_ms,
            "min_ms": r.min_ms,
            "max_ms": r.max_ms,
            "reliability_pct": r.reliability_pct,
            "error_count": r.error_count,
            "total_queries": r.total_queries,
            "reachable": r.reachable,
            "rank": r.rank,
        }
