"""Unit tests for the Flask API endpoints."""

import json
import unittest

import app as netoptimizer_app


class TestFlaskAPI(unittest.TestCase):
    """Tests for the Flask API routes."""

    def setUp(self):
        netoptimizer_app.app.testing = True
        self.client = netoptimizer_app.app.test_client()

    def test_index_page(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Dashboard", resp.data)

    def test_ping_page(self):
        resp = self.client.get("/ping")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Ping", resp.data)

    def test_dns_page(self):
        resp = self.client.get("/dns")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"DNS", resp.data)

    def test_cdn_page(self):
        resp = self.client.get("/cdn")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"CDN", resp.data)

    def test_protocol_page(self):
        resp = self.client.get("/protocol")
        self.assertEqual(resp.status_code, 200)

    def test_ports_page(self):
        resp = self.client.get("/ports")
        self.assertEqual(resp.status_code, 200)

    def test_recommendations_page(self):
        resp = self.client.get("/recommendations")
        self.assertEqual(resp.status_code, 200)

    def test_architecture_page(self):
        resp = self.client.get("/architecture")
        self.assertEqual(resp.status_code, 200)

    def test_report_page(self):
        resp = self.client.get("/report")
        self.assertEqual(resp.status_code, 200)

    def test_settings_get(self):
        resp = self.client.get("/api/settings")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertIn("restricted_mode", data)

    def test_settings_post(self):
        resp = self.client.post("/api/settings",
                                json={"restricted_mode": True},
                                content_type="application/json")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertTrue(data["restricted_mode"])

    def test_recommendations_api(self):
        resp = self.client.get("/api/recommendations")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertIn("recommendations", data)

    def test_architecture_api(self):
        resp = self.client.get("/api/architecture")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertIn("connection_type", data)

    def test_config_api(self):
        resp = self.client.get("/api/config")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertIn("template_config", data)

    def test_report_api(self):
        resp = self.client.get("/api/report")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertIn("generated_at", data)

    def test_report_export(self):
        resp = self.client.get("/api/report/export")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("application/json", resp.content_type)

    def test_dns_custom_no_ip(self):
        resp = self.client.post("/api/dns/custom",
                                json={"name": "Test"},
                                content_type="application/json")
        self.assertEqual(resp.status_code, 400)


if __name__ == "__main__":
    unittest.main()
