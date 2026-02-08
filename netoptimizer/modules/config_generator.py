"""Configuration template generator module.

Generates optimised connection parameter templates based on test results.
Templates are generic and software-independent.
"""

import json
import logging

logger = logging.getLogger(__name__)


class ConfigGenerator:
    """Generate optimised configuration templates from test results."""

    def generate(self, *, network: dict | None = None,
                 architecture: dict | None = None,
                 port_results: list[dict] | None = None) -> dict:
        """Generate a complete configuration template."""
        config = {
            "network_parameters": self._network_params(network),
            "connection_parameters": self._connection_params(network, architecture),
            "transport_parameters": self._transport_params(architecture),
            "reliability_parameters": self._reliability_params(network),
            "template_config": self._build_template(network, architecture, port_results),
        }
        return config

    def export_json(self, config: dict) -> str:
        """Export configuration as formatted JSON string."""
        return json.dumps(config, indent=2, ensure_ascii=False)

    # -- network parameters -------------------------------------------------

    def _network_params(self, network: dict | None) -> dict:
        mtu = 1400  # safe default
        if network:
            detected = network.get("mtu", 0)
            if detected > 0:
                mtu = detected - 28  # IP + TCP headers

        return {
            "mtu": mtu,
            "mss": mtu - 40,
            "fragment_strategy": "auto" if mtu >= 1400 else "pre-fragment",
            "detail": f"MTU set to {mtu} based on detection. "
                      f"MSS = {mtu - 40} to avoid IP fragmentation.",
        }

    # -- connection parameters ----------------------------------------------

    def _connection_params(self, network: dict | None,
                           architecture: dict | None) -> dict:
        stability = 80
        if network:
            stability = network.get("stability_score", 80)

        # Adjust timeouts based on stability
        if stability > 70:
            timeout = 30
            keepalive = 60
        elif stability > 40:
            timeout = 15
            keepalive = 30
        else:
            timeout = 10
            keepalive = 15

        return {
            "connect_timeout_s": timeout,
            "read_timeout_s": timeout * 2,
            "keepalive_interval_s": keepalive,
            "keepalive_probes": 3 if stability > 50 else 5,
            "idle_timeout_s": keepalive * 3,
            "detail": f"Timeouts tuned for {stability}% stability. "
                      f"Lower stability → more aggressive keepalive.",
        }

    # -- transport parameters -----------------------------------------------

    def _transport_params(self, architecture: dict | None) -> dict:
        transport = "TCP/TLS"
        if architecture:
            t = architecture.get("transport", {})
            transport = t.get("type", "TCP/TLS")

        multiplexing = "enabled" if "WebSocket" in transport or "Mux" in transport else "recommended"

        return {
            "transport_type": transport,
            "multiplexing": multiplexing,
            "max_concurrent_streams": 8,
            "buffer_size_kb": 64,
            "tcp_fast_open": True,
            "tcp_nodelay": True,
            "detail": f"Transport: {transport}. Multiplexing: {multiplexing}.",
        }

    # -- reliability parameters ---------------------------------------------

    def _reliability_params(self, network: dict | None) -> dict:
        stability = 80
        if network:
            stability = network.get("stability_score", 80)

        if stability > 70:
            retry_max = 3
            retry_delay = 5
            strategy = "linear"
        elif stability > 40:
            retry_max = 5
            retry_delay = 3
            strategy = "exponential"
        else:
            retry_max = 10
            retry_delay = 1
            strategy = "exponential_with_jitter"

        return {
            "retry_max": retry_max,
            "retry_initial_delay_s": retry_delay,
            "retry_strategy": strategy,
            "health_check_interval_s": 30 if stability > 50 else 15,
            "failover_threshold": 3,
            "detail": f"Retry strategy: {strategy} with max {retry_max} attempts. "
                      f"Adjusted for {stability}% stability.",
        }

    # -- full template ------------------------------------------------------

    def _build_template(self, network: dict | None,
                        architecture: dict | None,
                        port_results: list[dict] | None) -> dict:
        net = self._network_params(network)
        conn = self._connection_params(network, architecture)
        trans = self._transport_params(architecture)
        rel = self._reliability_params(network)

        # Determine port
        port = 443
        if port_results:
            reachable = [p for p in port_results if p.get("reachable")]
            if reachable:
                port = reachable[0]["port"]

        template = {
            "# NOTE": "This is a generic connection template. Adapt for your specific software.",
            "listen_port": port,
            "mtu": net["mtu"],
            "transport": trans["transport_type"],
            "multiplexing": trans["multiplexing"],
            "max_streams": trans["max_concurrent_streams"],
            "buffer_size_kb": trans["buffer_size_kb"],
            "tcp_fast_open": trans["tcp_fast_open"],
            "tcp_nodelay": trans["tcp_nodelay"],
            "connect_timeout": conn["connect_timeout_s"],
            "read_timeout": conn["read_timeout_s"],
            "keepalive_interval": conn["keepalive_interval_s"],
            "keepalive_probes": conn["keepalive_probes"],
            "idle_timeout": conn["idle_timeout_s"],
            "retry_max": rel["retry_max"],
            "retry_delay": rel["retry_initial_delay_s"],
            "retry_strategy": rel["retry_strategy"],
            "health_check_interval": rel["health_check_interval_s"],
            "failover_threshold": rel["failover_threshold"],
        }

        if architecture:
            dns = architecture.get("dns_config", {})
            template["dns_primary"] = dns.get("primary", "1.1.1.1")
            template["dns_secondary"] = dns.get("secondary", "8.8.8.8")

            loc = architecture.get("server_location", {})
            template["preferred_server_location"] = loc.get("location", "")

        return template
