"""Unit tests for the recommendation engine."""

import unittest

from modules.recommendation import RecommendationEngine


class TestRecommendationEngine(unittest.TestCase):
    """Tests for RecommendationEngine."""

    def setUp(self):
        self.engine = RecommendationEngine()

    def test_empty_input_returns_empty(self):
        recs = self.engine.generate()
        self.assertEqual(recs, [])

    def test_location_recs_with_results(self):
        ping_results = [
            {"host": "a.com", "country": "DE", "region": "Europe", "city": "Frankfurt",
             "avg_ms": 50, "min_ms": 40, "max_ms": 60, "jitter_ms": 5,
             "packet_loss_pct": 0, "reachable": True, "rank": 1},
            {"host": "b.com", "country": "US", "region": "North America", "city": "Newark",
             "avg_ms": 120, "min_ms": 100, "max_ms": 140, "jitter_ms": 10,
             "packet_loss_pct": 2, "reachable": True, "rank": 2},
        ]
        recs = self.engine.generate(ping_results=ping_results)
        categories = [r["category"] for r in recs]
        self.assertIn("Location", categories)
        loc_recs = [r for r in recs if r["category"] == "Location"]
        self.assertTrue(any("Frankfurt" in r["value"] for r in loc_recs))

    def test_dns_recs(self):
        dns_results = [
            {"name": "Cloudflare", "ip": "1.1.1.1", "avg_ms": 10, "min_ms": 8,
             "max_ms": 15, "reliability_pct": 100, "error_count": 0,
             "total_queries": 25, "reachable": True, "rank": 1},
            {"name": "Google", "ip": "8.8.8.8", "avg_ms": 20, "min_ms": 15,
             "max_ms": 30, "reliability_pct": 96, "error_count": 1,
             "total_queries": 25, "reachable": True, "rank": 2},
        ]
        recs = self.engine.generate(dns_results=dns_results)
        dns_recs = [r for r in recs if r["category"] == "DNS"]
        self.assertTrue(len(dns_recs) >= 1)
        self.assertIn("Cloudflare", dns_recs[0]["value"])

    def test_port_recs_no_reachable(self):
        port_results = [
            {"port": 80, "service": "HTTP", "protocol": "TCP",
             "reachable": False, "avg_ms": 9999, "stability_score": 0, "rank": 1},
        ]
        recs = self.engine.generate(port_results=port_results)
        port_recs = [r for r in recs if r["category"] == "Ports"]
        self.assertTrue(any("No Reachable" in r["title"] for r in port_recs))

    def test_network_recs_low_stability(self):
        network = {"stability_score": 30, "mtu": 1400, "nat_type": "Symmetric / Restricted NAT"}
        recs = self.engine.generate(network=network)
        categories = [r["category"] for r in recs]
        self.assertIn("Network", categories)
        net_recs = [r for r in recs if r["category"] == "Network"]
        self.assertTrue(any("Stability" in r["title"] for r in net_recs))

    def test_cdn_recs(self):
        cdn_results = [
            {"name": "Cloudflare", "host": "speed.cloudflare.com", "connect_ms": 30,
             "download_ms": 100, "total_ms": 130, "reachable": True,
             "stability_score": 92, "rank": 1},
        ]
        recs = self.engine.generate(cdn_results=cdn_results)
        cdn_recs = [r for r in recs if r["category"] == "CDN"]
        self.assertEqual(len(cdn_recs), 1)
        self.assertIn("Cloudflare", cdn_recs[0]["value"])

    def test_protocol_recs(self):
        protocol_results = [
            {"protocol": "TCP", "avg_ms": 50, "min_ms": 40, "max_ms": 60,
             "success_rate": 100, "targets_tested": 3, "rank": 1},
            {"protocol": "TLS Handshake", "avg_ms": 200, "min_ms": 150, "max_ms": 250,
             "success_rate": 95, "targets_tested": 3, "rank": 2},
        ]
        recs = self.engine.generate(protocol_results=protocol_results)
        proto_recs = [r for r in recs if r["category"] == "Protocol"]
        self.assertTrue(len(proto_recs) >= 1)

    def test_confidence_range(self):
        ping_results = [
            {"host": "a.com", "country": "DE", "region": "Europe", "city": "Frankfurt",
             "avg_ms": 50, "packet_loss_pct": 0, "reachable": True, "rank": 1},
        ]
        recs = self.engine.generate(ping_results=ping_results)
        for r in recs:
            self.assertGreaterEqual(r["confidence"], 0)
            self.assertLessEqual(r["confidence"], 100)


if __name__ == "__main__":
    unittest.main()
