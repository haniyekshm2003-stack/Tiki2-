"""Unit tests for the architecture builder."""

import unittest

from modules.architecture import ArchitectureBuilder


class TestArchitectureBuilder(unittest.TestCase):
    """Tests for ArchitectureBuilder."""

    def setUp(self):
        self.builder = ArchitectureBuilder()

    def test_empty_input(self):
        arch = self.builder.build()
        self.assertIn("connection_type", arch)
        self.assertIn("transport", arch)
        self.assertIn("encryption", arch)
        self.assertIn("fallback_plan", arch)

    def test_with_network_data(self):
        network = {"stability_score": 90, "mtu": 1500, "nat_type": "Full Cone NAT"}
        arch = self.builder.build(network=network)
        self.assertEqual(arch["connection_type"]["type"], "Direct Single Connection")

    def test_low_stability(self):
        network = {"stability_score": 20}
        arch = self.builder.build(network=network)
        self.assertIn("Multiplexed", arch["connection_type"]["type"])

    def test_port_protocol_combo(self):
        ports = [
            {"port": 443, "service": "HTTPS", "reachable": True, "avg_ms": 30, "stability_score": 90},
            {"port": 80, "service": "HTTP", "reachable": True, "avg_ms": 25, "stability_score": 85},
        ]
        arch = self.builder.build(port_results=ports)
        combos = arch["port_protocol_combo"]
        self.assertTrue(len(combos) >= 1)
        # 443 should be preferred
        self.assertEqual(combos[0]["port"], 443)

    def test_fallback_plan_has_levels(self):
        arch = self.builder.build()
        plan = arch["fallback_plan"]
        self.assertTrue(len(plan) >= 3)
        levels = [f["level"] for f in plan]
        self.assertEqual(levels, sorted(levels))

    def test_dns_recommendation_with_results(self):
        dns = [
            {"name": "Cloudflare", "ip": "1.1.1.1", "reachable": True, "reliability_pct": 100, "avg_ms": 10},
            {"name": "Google", "ip": "8.8.8.8", "reachable": True, "reliability_pct": 95, "avg_ms": 20},
        ]
        arch = self.builder.build(dns_results=dns)
        self.assertEqual(arch["dns_config"]["primary"], "1.1.1.1")
        self.assertEqual(arch["dns_config"]["secondary"], "8.8.8.8")

    def test_tunnel_category_443_available(self):
        ports = [
            {"port": 443, "service": "HTTPS", "reachable": True, "avg_ms": 30, "stability_score": 90},
        ]
        arch = self.builder.build(port_results=ports)
        self.assertIn("443", arch["tunnel_category"]["category"])

    def test_tunnel_category_no_standard_ports(self):
        ports = [
            {"port": 8080, "service": "HTTP Alt", "reachable": True, "avg_ms": 40, "stability_score": 80},
        ]
        arch = self.builder.build(port_results=ports)
        self.assertIn("8080", arch["tunnel_category"]["category"])


if __name__ == "__main__":
    unittest.main()
