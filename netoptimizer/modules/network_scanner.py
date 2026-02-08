"""Core network scanning module.

Provides deep analysis of the user's network connection including:
- Public/local IP detection
- ISP route quality analysis
- Latency, jitter, packet loss measurement
- TCP/UDP testing
- Throughput estimation
- MTU and fragmentation detection
- NAT type detection
- Connection stability measurement
"""

import asyncio
import logging
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Optional

import psutil
import requests

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ConnectionInfo:
    """Basic connection information."""
    public_ip: str = ""
    local_ip: str = ""
    isp: str = ""
    country: str = ""
    city: str = ""
    org: str = ""
    asn: str = ""
    timezone: str = ""


@dataclass
class LatencyResult:
    """Result of a latency measurement."""
    host: str = ""
    min_ms: float = 0.0
    max_ms: float = 0.0
    avg_ms: float = 0.0
    jitter_ms: float = 0.0
    packet_loss_pct: float = 0.0
    samples: int = 0


@dataclass
class ThroughputResult:
    """Result of a throughput test."""
    download_mbps: float = 0.0
    upload_mbps: float = 0.0
    test_duration_s: float = 0.0


@dataclass
class NetworkScanResult:
    """Comprehensive network scan result."""
    connection_info: ConnectionInfo = field(default_factory=ConnectionInfo)
    latency: LatencyResult = field(default_factory=LatencyResult)
    throughput: ThroughputResult = field(default_factory=ThroughputResult)
    mtu: int = 0
    nat_type: str = "Unknown"
    stability_score: float = 0.0
    tcp_accessible: bool = False
    udp_accessible: bool = False
    timestamp: float = 0.0


# ---------------------------------------------------------------------------
# Scanner implementation
# ---------------------------------------------------------------------------

class NetworkScanner:
    """Comprehensive network scanning engine."""

    TIMEOUT = 5
    PING_COUNT = 10
    STABILITY_SAMPLES = 20

    def __init__(self, restricted_mode: bool = False):
        self.restricted_mode = restricted_mode
        self._executor = ThreadPoolExecutor(max_workers=8)
        self._cache: dict = {}

    # -- public API ----------------------------------------------------------

    def full_scan(self) -> dict:
        """Run a complete network scan and return results as dict."""
        result = NetworkScanResult(timestamp=time.time())
        result.connection_info = self.detect_connection_info()
        result.latency = self.measure_latency("8.8.8.8")
        result.mtu = self.detect_mtu()
        result.nat_type = self.detect_nat_type()
        result.tcp_accessible = self.test_tcp("8.8.8.8", 53)
        result.udp_accessible = self.test_udp("8.8.8.8", 53)
        result.stability_score = self.measure_stability()
        result.throughput = self.estimate_throughput()
        return self._result_to_dict(result)

    # -- connection info -----------------------------------------------------

    def detect_connection_info(self) -> ConnectionInfo:
        """Detect public IP and connection information."""
        info = ConnectionInfo()
        try:
            info.local_ip = self._get_local_ip()
        except Exception as exc:
            logger.warning("Could not detect local IP: %s", exc)

        try:
            resp = requests.get("https://ipinfo.io/json", timeout=self.TIMEOUT)
            data = resp.json()
            info.public_ip = data.get("ip", "")
            info.isp = data.get("org", "")
            info.country = data.get("country", "")
            info.city = data.get("city", "")
            info.org = data.get("org", "")
            info.timezone = data.get("timezone", "")
        except Exception as exc:
            logger.warning("Could not detect public IP: %s", exc)
            try:
                resp = requests.get("https://api.ipify.org?format=json", timeout=self.TIMEOUT)
                info.public_ip = resp.json().get("ip", "")
            except Exception:
                pass
        return info

    # -- latency measurement -------------------------------------------------

    def measure_latency(self, host: str, count: Optional[int] = None) -> LatencyResult:
        """Measure latency to *host* using TCP connect timing."""
        count = count or self.PING_COUNT
        times: list[float] = []
        lost = 0

        for _ in range(count):
            try:
                start = time.perf_counter()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.TIMEOUT)
                sock.connect((host, 80))
                elapsed = (time.perf_counter() - start) * 1000
                times.append(elapsed)
                sock.close()
            except Exception:
                lost += 1
            if self.restricted_mode:
                time.sleep(0.2)

        result = LatencyResult(host=host, samples=count)
        if times:
            result.min_ms = round(min(times), 2)
            result.max_ms = round(max(times), 2)
            result.avg_ms = round(sum(times) / len(times), 2)
            diffs = [abs(times[i] - times[i - 1]) for i in range(1, len(times))]
            result.jitter_ms = round(sum(diffs) / len(diffs), 2) if diffs else 0.0
        result.packet_loss_pct = round(lost / count * 100, 2)
        return result

    # -- throughput estimation -----------------------------------------------

    def estimate_throughput(self) -> ThroughputResult:
        """Estimate download throughput using a small test file."""
        result = ThroughputResult()
        test_urls = [
            "https://speed.cloudflare.com/__down?bytes=1000000",
            "https://proof.ovh.net/files/1Mb.dat",
        ]
        for url in test_urls:
            try:
                start = time.perf_counter()
                resp = requests.get(url, timeout=15, stream=True)
                total = 0
                for chunk in resp.iter_content(chunk_size=8192):
                    total += len(chunk)
                elapsed = time.perf_counter() - start
                if elapsed > 0:
                    result.download_mbps = round((total * 8) / (elapsed * 1_000_000), 2)
                    result.test_duration_s = round(elapsed, 2)
                break
            except Exception as exc:
                logger.warning("Throughput test failed for %s: %s", url, exc)
        return result

    # -- MTU detection -------------------------------------------------------

    def detect_mtu(self) -> int:
        """Detect effective MTU using binary search on TCP packet size."""
        low, high = 500, 1500
        best = low
        while low <= high:
            mid = (low + high) // 2
            if self._test_packet_size("8.8.8.8", 53, mid):
                best = mid
                low = mid + 1
            else:
                high = mid - 1
        return best

    # -- NAT type detection --------------------------------------------------

    def detect_nat_type(self) -> str:
        """Detect NAT type using simple heuristics."""
        try:
            local_ip = self._get_local_ip()
            resp = requests.get("https://api.ipify.org?format=json", timeout=self.TIMEOUT)
            public_ip = resp.json().get("ip", "")
            if local_ip == public_ip:
                return "No NAT (Public IP)"
            # Try to bind multiple ports to infer NAT behaviour
            ports_ok = 0
            for port in [10000, 10001, 10002]:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.settimeout(2)
                    s.bind((local_ip, port))
                    s.close()
                    ports_ok += 1
                except Exception:
                    pass
            if ports_ok >= 2:
                return "Full Cone NAT"
            return "Symmetric / Restricted NAT"
        except Exception:
            return "Unknown"

    # -- TCP / UDP tests -----------------------------------------------------

    def test_tcp(self, host: str, port: int) -> bool:
        """Test TCP connectivity."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.TIMEOUT)
            s.connect((host, port))
            s.close()
            return True
        except Exception:
            return False

    def test_udp(self, host: str, port: int) -> bool:
        """Test UDP connectivity (send + optional recv)."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(self.TIMEOUT)
            s.sendto(b"\x00", (host, port))
            s.close()
            return True
        except Exception:
            return False

    # -- stability measurement -----------------------------------------------

    def measure_stability(self, host: str = "8.8.8.8") -> float:
        """Return a 0-100 stability score based on repeated latency checks."""
        samples: list[float] = []
        for _ in range(self.STABILITY_SAMPLES):
            try:
                start = time.perf_counter()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.TIMEOUT)
                s.connect((host, 80))
                elapsed = (time.perf_counter() - start) * 1000
                samples.append(elapsed)
                s.close()
            except Exception:
                samples.append(self.TIMEOUT * 1000)
            time.sleep(0.1 if not self.restricted_mode else 0.3)

        if not samples:
            return 0.0

        avg = sum(samples) / len(samples)
        variance = sum((s - avg) ** 2 for s in samples) / len(samples)
        std_dev = variance ** 0.5
        cv = std_dev / avg if avg else 1.0
        score = max(0, min(100, 100 - cv * 100))
        return round(score, 1)

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def _get_local_ip() -> str:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()

    def _test_packet_size(self, host: str, port: int, size: int) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.connect((host, port))
            s.send(b"\x00" * min(size, 1400))
            s.close()
            return True
        except Exception:
            return False

    @staticmethod
    def _result_to_dict(result: NetworkScanResult) -> dict:
        return {
            "connection_info": {
                "public_ip": result.connection_info.public_ip,
                "local_ip": result.connection_info.local_ip,
                "isp": result.connection_info.isp,
                "country": result.connection_info.country,
                "city": result.connection_info.city,
                "org": result.connection_info.org,
                "timezone": result.connection_info.timezone,
            },
            "latency": {
                "host": result.latency.host,
                "min_ms": result.latency.min_ms,
                "max_ms": result.latency.max_ms,
                "avg_ms": result.latency.avg_ms,
                "jitter_ms": result.latency.jitter_ms,
                "packet_loss_pct": result.latency.packet_loss_pct,
                "samples": result.latency.samples,
            },
            "throughput": {
                "download_mbps": result.throughput.download_mbps,
                "upload_mbps": result.throughput.upload_mbps,
                "test_duration_s": result.throughput.test_duration_s,
            },
            "mtu": result.mtu,
            "nat_type": result.nat_type,
            "stability_score": result.stability_score,
            "tcp_accessible": result.tcp_accessible,
            "udp_accessible": result.udp_accessible,
            "timestamp": result.timestamp,
        }
