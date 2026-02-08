"""Smart recommendation engine.

Analyses results from all test modules and produces intelligent
recommendations for DNS, CDN, server location, protocol, ports,
and connection architecture.
"""

import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class Recommendation:
    """A single recommendation with confidence score."""
    category: str
    title: str
    value: str
    detail: str
    confidence: float  # 0-100
    priority: int = 0  # lower is higher priority


class RecommendationEngine:
    """Analyse test data and produce actionable recommendations."""

    def generate(self, *, network: dict | None = None,
                 ping_results: list[dict] | None = None,
                 dns_results: list[dict] | None = None,
                 cdn_results: list[dict] | None = None,
                 protocol_results: list[dict] | None = None,
                 port_results: list[dict] | None = None) -> list[dict]:
        """Generate all recommendations from available test data."""
        recs: list[Recommendation] = []

        if ping_results:
            recs.extend(self._location_recs(ping_results))
        if dns_results:
            recs.extend(self._dns_recs(dns_results))
        if cdn_results:
            recs.extend(self._cdn_recs(cdn_results))
        if protocol_results:
            recs.extend(self._protocol_recs(protocol_results))
        if port_results:
            recs.extend(self._port_recs(port_results))
        if network:
            recs.extend(self._network_recs(network))

        recs.sort(key=lambda r: (r.priority, -r.confidence))
        return [self._to_dict(r) for r in recs]

    # -- location recommendations -------------------------------------------

    def _location_recs(self, results: list[dict]) -> list[Recommendation]:
        recs = []
        reachable = [r for r in results if r.get("reachable")]
        if not reachable:
            recs.append(Recommendation(
                category="Location",
                title="No reachable servers",
                value="N/A",
                detail="Could not reach any global test endpoints. Network may be severely restricted.",
                confidence=90,
                priority=1,
            ))
            return recs

        best = reachable[0]
        recs.append(Recommendation(
            category="Location",
            title="Best Server Location",
            value=f"{best['city']}, {best['country']}",
            detail=f"Lowest latency: {best['avg_ms']}ms to {best['host']}. "
                   f"Recommended for VPS/VPN endpoint.",
            confidence=min(95, 100 - best.get("packet_loss_pct", 0)),
            priority=1,
        ))

        # Top 3 regions
        regions: dict[str, list[float]] = {}
        for r in reachable:
            regions.setdefault(r.get("region", ""), []).append(r["avg_ms"])
        sorted_regions = sorted(regions.items(), key=lambda x: sum(x[1]) / len(x[1]))
        if sorted_regions:
            best_region = sorted_regions[0]
            avg = round(sum(best_region[1]) / len(best_region[1]), 1)
            recs.append(Recommendation(
                category="Location",
                title="Best Region",
                value=best_region[0],
                detail=f"Average latency {avg}ms across {len(best_region[1])} endpoints.",
                confidence=85,
                priority=2,
            ))

        return recs

    # -- DNS recommendations ------------------------------------------------

    def _dns_recs(self, results: list[dict]) -> list[Recommendation]:
        recs = []
        reachable = [r for r in results if r.get("reachable")]
        if not reachable:
            return recs

        best = reachable[0]
        recs.append(Recommendation(
            category="DNS",
            title="Best DNS Server",
            value=f"{best['name']} ({best['ip']})",
            detail=f"Average response: {best['avg_ms']}ms, "
                   f"reliability: {best['reliability_pct']}%.",
            confidence=best.get("reliability_pct", 80),
            priority=1,
        ))

        # Secondary recommendation
        if len(reachable) > 1:
            second = reachable[1]
            recs.append(Recommendation(
                category="DNS",
                title="Secondary DNS",
                value=f"{second['name']} ({second['ip']})",
                detail=f"Average response: {second['avg_ms']}ms. Use as fallback.",
                confidence=second.get("reliability_pct", 70),
                priority=3,
            ))

        return recs

    # -- CDN recommendations ------------------------------------------------

    def _cdn_recs(self, results: list[dict]) -> list[Recommendation]:
        recs = []
        reachable = [r for r in results if r.get("reachable")]
        if not reachable:
            return recs

        best = reachable[0]
        recs.append(Recommendation(
            category="CDN",
            title="Best CDN",
            value=best["name"],
            detail=f"Total latency: {best['total_ms']}ms, "
                   f"stability: {best['stability_score']}%.",
            confidence=best.get("stability_score", 80),
            priority=2,
        ))
        return recs

    # -- protocol recommendations -------------------------------------------

    def _protocol_recs(self, results: list[dict]) -> list[Recommendation]:
        recs = []
        working = [r for r in results if r.get("success_rate", 0) > 50]
        if not working:
            return recs

        best = min(working, key=lambda r: r["avg_ms"])
        recs.append(Recommendation(
            category="Protocol",
            title="Best Protocol",
            value=best["protocol"],
            detail=f"Average latency: {best['avg_ms']}ms, "
                   f"success rate: {best['success_rate']}%.",
            confidence=best.get("success_rate", 80),
            priority=2,
        ))

        # TLS recommendation
        tls = [r for r in working if "TLS" in r.get("protocol", "")]
        if tls:
            t = tls[0]
            recs.append(Recommendation(
                category="Protocol",
                title="TLS Performance",
                value=f"{t['avg_ms']}ms handshake",
                detail=f"TLS handshake average: {t['avg_ms']}ms. "
                       f"{'Good' if t['avg_ms'] < 500 else 'Consider optimisation'}.",
                confidence=80,
                priority=3,
            ))

        return recs

    # -- port recommendations -----------------------------------------------

    def _port_recs(self, results: list[dict]) -> list[Recommendation]:
        recs = []
        reachable = [r for r in results if r.get("reachable")]
        if not reachable:
            recs.append(Recommendation(
                category="Ports",
                title="No Reachable Ports",
                value="N/A",
                detail="No outbound ports are reachable. Network is severely restricted.",
                confidence=95,
                priority=1,
            ))
            return recs

        # Best port
        best = reachable[0]
        recs.append(Recommendation(
            category="Ports",
            title="Best Port",
            value=f"{best['port']} ({best['service']})",
            detail=f"Latency: {best['avg_ms']}ms, stability: {best['stability_score']}%.",
            confidence=best.get("stability_score", 80),
            priority=2,
        ))

        # Port range
        stable = [r for r in reachable if r.get("stability_score", 0) > 70]
        if stable:
            ports = sorted(r["port"] for r in stable)
            recs.append(Recommendation(
                category="Ports",
                title="Stable Port Range",
                value=", ".join(str(p) for p in ports[:10]),
                detail=f"{len(stable)} ports with >70% stability score.",
                confidence=75,
                priority=3,
            ))

        return recs

    # -- general network recommendations ------------------------------------

    def _network_recs(self, network: dict) -> list[Recommendation]:
        recs = []

        # MTU
        mtu = network.get("mtu", 0)
        if mtu:
            rec_mtu = mtu - 28  # IP + TCP header
            recs.append(Recommendation(
                category="Network",
                title="Recommended MTU",
                value=str(rec_mtu),
                detail=f"Detected MTU: {mtu}. Recommended payload MTU: {rec_mtu} "
                       f"to avoid fragmentation.",
                confidence=80,
                priority=3,
            ))

        # Stability
        stability = network.get("stability_score", 0)
        if stability < 50:
            recs.append(Recommendation(
                category="Network",
                title="Connection Stability Warning",
                value=f"{stability}%",
                detail="Connection stability is low. Consider multiplexing and "
                       "aggressive retry strategies.",
                confidence=90,
                priority=1,
            ))

        # NAT
        nat = network.get("nat_type", "")
        if "Symmetric" in nat:
            recs.append(Recommendation(
                category="Network",
                title="NAT Type Alert",
                value=nat,
                detail="Symmetric NAT detected. May limit P2P and some VPN protocols.",
                confidence=75,
                priority=2,
            ))

        return recs

    @staticmethod
    def _to_dict(r: Recommendation) -> dict:
        return {
            "category": r.category,
            "title": r.title,
            "value": r.value,
            "detail": r.detail,
            "confidence": r.confidence,
            "priority": r.priority,
        }
