"""Global ping testing module.

Tests latency to servers across different countries and regions,
ranks them, and suggests the best locations for VPS/VPN/Proxy usage.
"""

import logging
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Global test endpoints – diverse geographic coverage
# ---------------------------------------------------------------------------

GLOBAL_ENDPOINTS: list[dict] = [
    # Europe
    {"host": "speedtest.london.linode.com", "country": "UK", "region": "Europe", "city": "London"},
    {"host": "speedtest.frankfurt.linode.com", "country": "DE", "region": "Europe", "city": "Frankfurt"},
    {"host": "speedtest.amsterdam.linode.com", "country": "NL", "region": "Europe", "city": "Amsterdam"},
    {"host": "ping.online.net", "country": "FR", "region": "Europe", "city": "Paris"},
    {"host": "speedtest.mil01.softlayer.com", "country": "IT", "region": "Europe", "city": "Milan"},
    # North America
    {"host": "speedtest.newark.linode.com", "country": "US", "region": "North America", "city": "Newark"},
    {"host": "speedtest.dallas.linode.com", "country": "US", "region": "North America", "city": "Dallas"},
    {"host": "speedtest.fremont.linode.com", "country": "US", "region": "North America", "city": "Fremont"},
    {"host": "speedtest.toronto1.linode.com", "country": "CA", "region": "North America", "city": "Toronto"},
    # Asia
    {"host": "speedtest.tokyo2.linode.com", "country": "JP", "region": "Asia", "city": "Tokyo"},
    {"host": "speedtest.singapore.linode.com", "country": "SG", "region": "Asia", "city": "Singapore"},
    {"host": "speedtest.mumbai1.linode.com", "country": "IN", "region": "Asia", "city": "Mumbai"},
    # Middle East
    {"host": "speedtest.uaeexchange.com", "country": "AE", "region": "Middle East", "city": "Dubai"},
    # Oceania
    {"host": "speedtest.syd1.linode.com", "country": "AU", "region": "Oceania", "city": "Sydney"},
    # South America
    {"host": "speedtest.sao01.softlayer.com", "country": "BR", "region": "South America", "city": "São Paulo"},
]


@dataclass
class PingResult:
    """Single endpoint ping result."""
    host: str
    country: str
    region: str
    city: str
    avg_ms: float
    min_ms: float
    max_ms: float
    jitter_ms: float
    packet_loss_pct: float
    reachable: bool
    rank: int = 0


class PingTester:
    """Tests latency to global endpoints and ranks locations."""

    TIMEOUT = 5
    SAMPLES = 5

    def __init__(self, restricted_mode: bool = False, max_workers: int = 10):
        self.restricted_mode = restricted_mode
        self.max_workers = max_workers

    def test_all(self, endpoints: list[dict] | None = None) -> list[dict]:
        """Test all endpoints in parallel and return ranked results."""
        eps = endpoints or GLOBAL_ENDPOINTS
        results: list[PingResult] = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {
                pool.submit(self._test_endpoint, ep): ep for ep in eps
            }
            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except Exception as exc:
                    ep = futures[future]
                    logger.warning("Ping test failed for %s: %s", ep["host"], exc)

        # Sort by avg latency (unreachable last)
        results.sort(key=lambda r: (not r.reachable, r.avg_ms))
        for idx, r in enumerate(results, 1):
            r.rank = idx

        return [self._to_dict(r) for r in results]

    def test_single(self, host: str, country: str = "", region: str = "", city: str = "") -> dict:
        """Test a single host."""
        ep = {"host": host, "country": country, "region": region, "city": city}
        result = self._test_endpoint(ep)
        return self._to_dict(result)

    def get_best_locations(self, results: list[dict], top_n: int = 5) -> list[dict]:
        """Return the top N best locations from results."""
        reachable = [r for r in results if r.get("reachable")]
        return reachable[:top_n]

    def get_region_summary(self, results: list[dict]) -> list[dict]:
        """Summarise results by region."""
        regions: dict[str, list[float]] = {}
        for r in results:
            if r.get("reachable"):
                regions.setdefault(r["region"], []).append(r["avg_ms"])
        summary = []
        for region, latencies in regions.items():
            summary.append({
                "region": region,
                "avg_ms": round(sum(latencies) / len(latencies), 2),
                "best_ms": round(min(latencies), 2),
                "endpoints_tested": len(latencies),
            })
        summary.sort(key=lambda s: s["avg_ms"])
        return summary

    # -- internals -----------------------------------------------------------

    def _test_endpoint(self, ep: dict) -> PingResult:
        times: list[float] = []
        lost = 0
        for _ in range(self.SAMPLES):
            try:
                start = time.perf_counter()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.TIMEOUT)
                s.connect((ep["host"], 80))
                elapsed = (time.perf_counter() - start) * 1000
                times.append(elapsed)
                s.close()
            except Exception:
                lost += 1
            if self.restricted_mode:
                time.sleep(0.3)

        reachable = len(times) > 0
        avg = round(sum(times) / len(times), 2) if times else 9999
        mn = round(min(times), 2) if times else 9999
        mx = round(max(times), 2) if times else 9999
        diffs = [abs(times[i] - times[i - 1]) for i in range(1, len(times))]
        jitter = round(sum(diffs) / len(diffs), 2) if diffs else 0

        return PingResult(
            host=ep["host"],
            country=ep.get("country", ""),
            region=ep.get("region", ""),
            city=ep.get("city", ""),
            avg_ms=avg,
            min_ms=mn,
            max_ms=mx,
            jitter_ms=jitter,
            packet_loss_pct=round(lost / self.SAMPLES * 100, 2),
            reachable=reachable,
        )

    @staticmethod
    def _to_dict(r: PingResult) -> dict:
        return {
            "host": r.host,
            "country": r.country,
            "region": r.region,
            "city": r.city,
            "avg_ms": r.avg_ms,
            "min_ms": r.min_ms,
            "max_ms": r.max_ms,
            "jitter_ms": r.jitter_ms,
            "packet_loss_pct": r.packet_loss_pct,
            "reachable": r.reachable,
            "rank": r.rank,
        }
