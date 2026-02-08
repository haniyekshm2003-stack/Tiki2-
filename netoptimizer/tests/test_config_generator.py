"""Unit tests for the config generator."""

import json
import unittest

from modules.config_generator import ConfigGenerator


class TestConfigGenerator(unittest.TestCase):
    """Tests for ConfigGenerator."""

    def setUp(self):
        self.gen = ConfigGenerator()

    def test_default_config(self):
        config = self.gen.generate()
        self.assertIn("network_parameters", config)
        self.assertIn("connection_parameters", config)
        self.assertIn("transport_parameters", config)
        self.assertIn("reliability_parameters", config)
        self.assertIn("template_config", config)

    def test_mtu_calculation(self):
        network = {"mtu": 1500, "stability_score": 80}
        config = self.gen.generate(network=network)
        self.assertEqual(config["network_parameters"]["mtu"], 1472)  # 1500 - 28

    def test_low_stability_aggressive_retry(self):
        network = {"stability_score": 20, "mtu": 1400}
        config = self.gen.generate(network=network)
        rel = config["reliability_parameters"]
        self.assertEqual(rel["retry_strategy"], "exponential_with_jitter")
        self.assertGreater(rel["retry_max"], 5)

    def test_high_stability_conservative_retry(self):
        network = {"stability_score": 90, "mtu": 1500}
        config = self.gen.generate(network=network)
        rel = config["reliability_parameters"]
        self.assertEqual(rel["retry_strategy"], "linear")

    def test_template_has_port(self):
        ports = [
            {"port": 443, "service": "HTTPS", "reachable": True, "avg_ms": 30},
        ]
        config = self.gen.generate(port_results=ports)
        self.assertEqual(config["template_config"]["listen_port"], 443)

    def test_export_json(self):
        config = self.gen.generate()
        exported = self.gen.export_json(config)
        parsed = json.loads(exported)
        self.assertIn("template_config", parsed)

    def test_transport_default(self):
        config = self.gen.generate()
        self.assertEqual(config["transport_parameters"]["transport_type"], "TCP/TLS")


if __name__ == "__main__":
    unittest.main()
