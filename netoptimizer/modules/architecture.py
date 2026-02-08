"""Service architecture builder module.

Generates recommended connection architecture based on real test results,
including protocol categories, transport types, port combinations,
and fallback strategies.
"""

import logging

logger = logging.getLogger(__name__)


class ArchitectureBuilder:
    """Build a recommended service connection architecture from test data."""

    def build(self, *, network: dict | None = None,
              ping_results: list[dict] | None = None,
              dns_results: list[dict] | None = None,
              cdn_results: list[dict] | None = None,
              protocol_results: list[dict] | None = None,
              port_results: list[dict] | None = None) -> dict:
        """Generate a complete architecture recommendation."""

        arch: dict = {
            "connection_type": self._recommend_connection_type(network, protocol_results),
            "transport": self._recommend_transport(protocol_results),
            "encryption": self._recommend_encryption(protocol_results),
            "tunnel_category": self._recommend_tunnel_category(port_results, protocol_results),
            "port_protocol_combo": self._recommend_port_protocol(port_results, protocol_results),
            "fallback_plan": self._build_fallback_plan(port_results, protocol_results),
            "server_location": self._recommend_location(ping_results),
            "dns_config": self._recommend_dns(dns_results),
            "cdn_strategy": self._recommend_cdn_strategy(cdn_results),
        }
        return arch

    # -- connection type ----------------------------------------------------

    def _recommend_connection_type(self, network: dict | None,
                                   protocols: list[dict] | None) -> dict:
        recommendation = {
            "type": "Direct Encrypted Tunnel",
            "detail": "Standard encrypted tunnel with TLS-based transport",
            "confidence": 70,
        }

        if network:
            stability = network.get("stability_score", 50)
            if stability < 40:
                recommendation["type"] = "Multiplexed Tunnel with Redundancy"
                recommendation["detail"] = (
                    "Low stability detected. Use multiplexed connections "
                    "with automatic failover."
                )
                recommendation["confidence"] = 85
            elif stability > 80:
                recommendation["type"] = "Direct Single Connection"
                recommendation["detail"] = (
                    "High stability. Simple direct connection is sufficient."
                )
                recommendation["confidence"] = 90

        if protocols:
            https_results = [p for p in protocols if p.get("protocol") == "HTTPS"]
            if https_results and https_results[0].get("success_rate", 0) < 50:
                recommendation["type"] = "Obfuscated Transport"
                recommendation["detail"] = (
                    "HTTPS has low success rate. Consider obfuscated or "
                    "CDN-fronted transport."
                )
                recommendation["confidence"] = 80

        return recommendation

    # -- transport ----------------------------------------------------------

    def _recommend_transport(self, protocols: list[dict] | None) -> dict:
        if not protocols:
            return {"type": "TCP/TLS", "detail": "Default recommendation", "confidence": 60}

        tcp = [p for p in protocols if p.get("protocol") == "TCP"]
        udp = [p for p in protocols if p.get("protocol") == "UDP"]
        ws = [p for p in protocols if "WebSocket" in p.get("protocol", "")]

        tcp_ok = tcp and tcp[0].get("success_rate", 0) > 70
        udp_ok = udp and udp[0].get("success_rate", 0) > 70
        ws_ok = ws and ws[0].get("success_rate", 0) > 70

        if ws_ok and tcp_ok:
            return {
                "type": "WebSocket over TLS",
                "detail": "Both TCP and WebSocket performing well. WebSocket over TLS recommended for flexibility.",
                "confidence": 85,
            }
        elif tcp_ok and not udp_ok:
            return {
                "type": "TCP/TLS",
                "detail": "TCP is reliable but UDP is restricted. Use TCP-based transport.",
                "confidence": 80,
            }
        elif udp_ok:
            return {
                "type": "UDP-based (QUIC-like)",
                "detail": "UDP is available and performing well. Consider QUIC or UDP-based transport for lower latency.",
                "confidence": 75,
            }
        else:
            return {
                "type": "TCP/TLS with CDN fronting",
                "detail": "Limited protocol availability. Use CDN-fronted TCP for reliability.",
                "confidence": 70,
            }

    # -- encryption ---------------------------------------------------------

    def _recommend_encryption(self, protocols: list[dict] | None) -> dict:
        rec = {
            "category": "TLS 1.3",
            "detail": "Modern TLS 1.3 recommended for best security and performance.",
            "confidence": 85,
        }

        if protocols:
            tls = [p for p in protocols if "TLS" in p.get("protocol", "")]
            if tls and tls[0].get("avg_ms", 9999) > 1000:
                rec["category"] = "TLS 1.3 with session resumption"
                rec["detail"] = (
                    "TLS handshake is slow. Use session resumption (0-RTT) to reduce overhead."
                )
                rec["confidence"] = 80

        return rec

    # -- tunnel category ----------------------------------------------------

    def _recommend_tunnel_category(self, ports: list[dict] | None,
                                    protocols: list[dict] | None) -> dict:
        if not ports:
            return {
                "category": "HTTPS-based Tunnel",
                "detail": "Default: tunnel over HTTPS (port 443)",
                "confidence": 65,
            }

        reachable_ports = [p for p in ports if p.get("reachable")]
        has_443 = any(p["port"] == 443 for p in reachable_ports)
        has_80 = any(p["port"] == 80 for p in reachable_ports)

        if has_443:
            return {
                "category": "TLS-based Tunnel (port 443)",
                "detail": "Port 443 is available and stable. Standard TLS tunnel recommended.",
                "confidence": 90,
            }
        elif has_80:
            return {
                "category": "HTTP-wrapped Tunnel (port 80)",
                "detail": "Port 443 may be restricted. Use HTTP-based tunnel with internal encryption.",
                "confidence": 75,
            }
        else:
            alt_ports = [p for p in reachable_ports if p["port"] not in (80, 443)]
            if alt_ports:
                return {
                    "category": f"Alternative Port Tunnel (port {alt_ports[0]['port']})",
                    "detail": f"Standard ports restricted. Use port {alt_ports[0]['port']} ({alt_ports[0].get('service', '')}).",
                    "confidence": 65,
                }
            return {
                "category": "CDN-fronted Tunnel",
                "detail": "Most ports restricted. Use CDN fronting for connectivity.",
                "confidence": 60,
            }

    # -- port + protocol combo ----------------------------------------------

    def _recommend_port_protocol(self, ports: list[dict] | None,
                                  protocols: list[dict] | None) -> list[dict]:
        combos = []
        if not ports:
            combos.append({"port": 443, "protocol": "TLS/TCP", "confidence": 70})
            return combos

        reachable = [p for p in ports if p.get("reachable")]
        # Prefer 443, then 80, then others
        preferred_order = [443, 80, 8443, 8080, 2083, 2096]
        sorted_ports = sorted(reachable, key=lambda p: (
            preferred_order.index(p["port"]) if p["port"] in preferred_order else 999,
            p["avg_ms"],
        ))

        for p in sorted_ports[:5]:
            proto = "TLS/TCP" if p["port"] in (443, 8443, 2083, 2096) else "TCP"
            combos.append({
                "port": p["port"],
                "protocol": proto,
                "service": p.get("service", ""),
                "latency_ms": p["avg_ms"],
                "stability": p.get("stability_score", 0),
                "confidence": min(90, p.get("stability_score", 50)),
            })

        return combos

    # -- fallback plan ------------------------------------------------------

    def _build_fallback_plan(self, ports: list[dict] | None,
                              protocols: list[dict] | None) -> list[dict]:
        plan = []
        plan.append({
            "level": 1,
            "strategy": "Primary: TLS tunnel on port 443",
            "detail": "Standard encrypted connection.",
        })
        plan.append({
            "level": 2,
            "strategy": "Fallback 1: WebSocket over TLS on port 443",
            "detail": "If direct TLS fails, wrap traffic in WebSocket.",
        })
        plan.append({
            "level": 3,
            "strategy": "Fallback 2: CDN-fronted connection",
            "detail": "Route through CDN edge to bypass path restrictions.",
        })

        if ports:
            alt = [p for p in ports if p.get("reachable") and p["port"] not in (80, 443)]
            if alt:
                plan.append({
                    "level": 4,
                    "strategy": f"Fallback 3: Alternative port {alt[0]['port']}",
                    "detail": f"Use non-standard port {alt[0]['port']} ({alt[0].get('service', '')}).",
                })

        plan.append({
            "level": len(plan) + 1,
            "strategy": "Last resort: Fragment + obfuscate on any available port",
            "detail": "Maximum obfuscation with fragmented packets.",
        })

        return plan

    # -- location -----------------------------------------------------------

    def _recommend_location(self, ping_results: list[dict] | None) -> dict:
        if not ping_results:
            return {"location": "Europe (default)", "confidence": 50}

        reachable = [r for r in ping_results if r.get("reachable")]
        if not reachable:
            return {"location": "Unknown", "confidence": 20}

        best = reachable[0]
        return {
            "location": f"{best.get('city', '')}, {best.get('country', '')}",
            "latency_ms": best["avg_ms"],
            "confidence": min(95, 100 - best.get("packet_loss_pct", 0)),
        }

    # -- DNS ----------------------------------------------------------------

    def _recommend_dns(self, dns_results: list[dict] | None) -> dict:
        if not dns_results:
            return {"primary": "1.1.1.1", "secondary": "8.8.8.8", "confidence": 60}

        reachable = [d for d in dns_results if d.get("reachable")]
        if len(reachable) >= 2:
            return {
                "primary": reachable[0]["ip"],
                "primary_name": reachable[0]["name"],
                "secondary": reachable[1]["ip"],
                "secondary_name": reachable[1]["name"],
                "confidence": reachable[0].get("reliability_pct", 80),
            }
        elif reachable:
            return {
                "primary": reachable[0]["ip"],
                "primary_name": reachable[0]["name"],
                "secondary": "1.1.1.1",
                "confidence": reachable[0].get("reliability_pct", 70),
            }
        return {"primary": "1.1.1.1", "secondary": "8.8.8.8", "confidence": 50}

    # -- CDN ----------------------------------------------------------------

    def _recommend_cdn_strategy(self, cdn_results: list[dict] | None) -> dict:
        if not cdn_results:
            return {"strategy": "Use Cloudflare CDN (default)", "confidence": 60}

        reachable = [c for c in cdn_results if c.get("reachable")]
        if not reachable:
            return {"strategy": "No CDN reachable", "confidence": 30}

        best = reachable[0]
        return {
            "strategy": f"Use {best['name']} as primary CDN",
            "latency_ms": best.get("total_ms", 0),
            "stability": best.get("stability_score", 0),
            "confidence": best.get("stability_score", 70),
        }
