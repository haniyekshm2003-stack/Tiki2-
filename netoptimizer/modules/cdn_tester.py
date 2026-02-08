"""CDN testing and edge network analysis module.

Tests latency and reachability of major CDN networks,
compares route quality, and recommends the best CDN for the user's network.
"""

import logging
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

import requests

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# CDN test endpoints
# ---------------------------------------------------------------------------

CDN_ENDPOINTS: list[dict] = [
    {"name": "Cloudflare", "host": "speed.cloudflare.com", "test_url": "https://speed.cloudflare.com/__down?bytes=10000"},
    {"name": "Google CDN", "host": "www.gstatic.com", "test_url": "https://www.gstatic.com/generate_204"},
    {"name": "Amazon CloudFront", "host": "d1.awsstatic.com", "test_url": "https://d1.awsstatic.com/logos/aws-logo-lockups/poweredbyaws/PB_AWS_logo_RGB_REV_SQ.8c88ac215fe4e441dc42865dd6962ed4f444a90d.png"},
    {"name": "Fastly", "host": "www.fastly.com", "test_url": "https://www.fastly.com/"},
    {"name": "Akamai", "host": "www.akamai.com", "test_url": "https://www.akamai.com/"},
    {"name": "Microsoft Azure CDN", "host": "ajax.aspnetcdn.com", "test_url": "https://ajax.aspnetcdn.com/ajax/jquery/jquery-3.7.1.min.js"},
    {"name": "jsDelivr", "host": "cdn.jsdelivr.net", "test_url": "https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js"},
    {"name": "cdnjs (Cloudflare)", "host": "cdnjs.cloudflare.com", "test_url": "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js"},
    {"name": "StackPath", "host": "www.stackpath.com", "test_url": "https://www.stackpath.com/"},
    {"name": "KeyCDN", "host": "www.keycdn.com", "test_url": "https://www.keycdn.com/"},
]


@dataclass
class CDNResult:
    """Result of a CDN endpoint test."""
    name: str
    host: str
    connect_ms: float
    download_ms: float
    total_ms: float
    reachable: bool
    stability_score: float
    rank: int = 0


class CDNTester:
    """Test and compare CDN edge networks."""

    TIMEOUT = 10
    SAMPLES = 3

    def __init__(self, restricted_mode: bool = False, max_workers: int = 6):
        self.restricted_mode = restricted_mode
        self.max_workers = max_workers

    def test_all(self, endpoints: list[dict] | None = None) -> list[dict]:
        """Test all CDN endpoints and return ranked results."""
        eps = endpoints or CDN_ENDPOINTS
        results: list[CDNResult] = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {
                pool.submit(self._test_cdn, ep): ep for ep in eps
            }
            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except Exception as exc:
                    ep = futures[future]
                    logger.warning("CDN test failed for %s: %s", ep["name"], exc)

        results.sort(key=lambda r: (not r.reachable, r.total_ms))
        for idx, r in enumerate(results, 1):
            r.rank = idx

        return [self._to_dict(r) for r in results]

    def get_best_cdn(self, results: list[dict], top_n: int = 3) -> list[dict]:
        """Return the best CDN options."""
        reachable = [r for r in results if r.get("reachable")]
        return reachable[:top_n]

    # -- internals -----------------------------------------------------------

    def _test_cdn(self, ep: dict) -> CDNResult:
        connect_times: list[float] = []
        download_times: list[float] = []
        failures = 0

        for _ in range(self.SAMPLES):
            try:
                # TCP connect time
                start = time.perf_counter()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.TIMEOUT)
                s.connect((ep["host"], 443))
                connect_ms = (time.perf_counter() - start) * 1000
                connect_times.append(connect_ms)
                s.close()

                # HTTP download time
                start = time.perf_counter()
                requests.get(ep["test_url"], timeout=self.TIMEOUT)
                dl_ms = (time.perf_counter() - start) * 1000
                download_times.append(dl_ms)
            except Exception:
                failures += 1
            if self.restricted_mode:
                time.sleep(0.5)

        reachable = len(connect_times) > 0
        avg_connect = round(sum(connect_times) / len(connect_times), 2) if connect_times else 9999
        avg_download = round(sum(download_times) / len(download_times), 2) if download_times else 9999
        total = round(avg_connect + avg_download, 2) if reachable else 9999

        # Stability based on variance
        stability = 0.0
        if connect_times and len(connect_times) > 1:
            avg = sum(connect_times) / len(connect_times)
            var = sum((t - avg) ** 2 for t in connect_times) / len(connect_times)
            cv = (var ** 0.5) / avg if avg else 1
            stability = round(max(0, min(100, 100 - cv * 100)), 1)

        return CDNResult(
            name=ep["name"],
            host=ep["host"],
            connect_ms=avg_connect,
            download_ms=avg_download,
            total_ms=total,
            reachable=reachable,
            stability_score=stability,
        )

    @staticmethod
    def _to_dict(r: CDNResult) -> dict:
        return {
            "name": r.name,
            "host": r.host,
            "connect_ms": r.connect_ms,
            "download_ms": r.download_ms,
            "total_ms": r.total_ms,
            "reachable": r.reachable,
            "stability_score": r.stability_score,
            "rank": r.rank,
        }
