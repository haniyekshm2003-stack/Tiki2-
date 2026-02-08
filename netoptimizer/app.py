"""Network Optimizer Pro – Main Flask application.

Provides a local web dashboard for running network tests and viewing results.
All tests run from the user's real network connection.

Usage:
    python app.py          # starts dashboard on http://localhost:5000
    python app.py --port 8080  # custom port
"""

import argparse
import json
import logging
import os
import sys
import threading
import time

from flask import Flask, jsonify, render_template, request

# Add parent to path so modules resolve when running directly
sys.path.insert(0, os.path.dirname(__file__))

from modules.network_scanner import NetworkScanner
from modules.ping_tester import PingTester
from modules.dns_analyzer import DNSAnalyzer
from modules.cdn_tester import CDNTester
from modules.protocol_tester import ProtocolTester
from modules.port_scanner import PortScanner
from modules.recommendation import RecommendationEngine
from modules.architecture import ArchitectureBuilder
from modules.config_generator import ConfigGenerator

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("netoptimizer")

# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------

app = Flask(__name__)

# Shared state ---------------------------------------------------------------
_results: dict = {}
_lock = threading.Lock()
_restricted_mode = False


def _store(key: str, value):
    with _lock:
        _results[key] = value


def _get(key: str, default=None):
    with _lock:
        return _results.get(key, default)


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/ping")
def ping_page():
    return render_template("ping_test.html")


@app.route("/dns")
def dns_page():
    return render_template("dns_test.html")


@app.route("/cdn")
def cdn_page():
    return render_template("cdn_test.html")


@app.route("/protocol")
def protocol_page():
    return render_template("protocol_test.html")


@app.route("/ports")
def ports_page():
    return render_template("port_scan.html")


@app.route("/recommendations")
def recommendations_page():
    return render_template("recommendations.html")


@app.route("/architecture")
def architecture_page():
    return render_template("architecture.html")


@app.route("/report")
def report_page():
    return render_template("report.html")


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------

@app.route("/api/settings", methods=["GET", "POST"])
def api_settings():
    global _restricted_mode
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        _restricted_mode = bool(data.get("restricted_mode", False))
        return jsonify({"restricted_mode": _restricted_mode})
    return jsonify({"restricted_mode": _restricted_mode})


@app.route("/api/network/scan", methods=["POST"])
def api_network_scan():
    scanner = NetworkScanner(restricted_mode=_restricted_mode)
    result = scanner.full_scan()
    _store("network", result)
    return jsonify(result)


@app.route("/api/network/info", methods=["GET"])
def api_network_info():
    scanner = NetworkScanner(restricted_mode=_restricted_mode)
    info = scanner.detect_connection_info()
    data = {
        "public_ip": info.public_ip,
        "local_ip": info.local_ip,
        "isp": info.isp,
        "country": info.country,
        "city": info.city,
        "org": info.org,
        "timezone": info.timezone,
    }
    return jsonify(data)


@app.route("/api/ping/test", methods=["POST"])
def api_ping_test():
    tester = PingTester(restricted_mode=_restricted_mode)
    results = tester.test_all()
    region_summary = tester.get_region_summary(results)
    best = tester.get_best_locations(results)
    data = {"results": results, "region_summary": region_summary, "best_locations": best}
    _store("ping", data)
    return jsonify(data)


@app.route("/api/dns/benchmark", methods=["POST"])
def api_dns_benchmark():
    analyzer = DNSAnalyzer(restricted_mode=_restricted_mode)
    results = analyzer.benchmark_all()
    best = analyzer.get_best_dns(results)
    data = {"results": results, "best_dns": best}
    _store("dns", data)
    return jsonify(data)


@app.route("/api/dns/custom", methods=["POST"])
def api_dns_custom():
    body = request.get_json(silent=True) or {}
    name = body.get("name", "Custom")
    ip = body.get("ip", "")
    if not ip:
        return jsonify({"error": "IP required"}), 400
    analyzer = DNSAnalyzer(restricted_mode=_restricted_mode)
    result = analyzer.benchmark_custom(name, ip)
    return jsonify(result)


@app.route("/api/cdn/test", methods=["POST"])
def api_cdn_test():
    tester = CDNTester(restricted_mode=_restricted_mode)
    results = tester.test_all()
    best = tester.get_best_cdn(results)
    data = {"results": results, "best_cdn": best}
    _store("cdn", data)
    return jsonify(data)


@app.route("/api/protocol/benchmark", methods=["POST"])
def api_protocol_benchmark():
    tester = ProtocolTester(restricted_mode=_restricted_mode)
    results = tester.benchmark_all()
    data = {"results": results}
    _store("protocol", data)
    return jsonify(data)


@app.route("/api/ports/scan", methods=["POST"])
def api_port_scan():
    scanner = PortScanner(restricted_mode=_restricted_mode)
    results = scanner.scan_all()
    reachable = scanner.get_reachable_ports(results)
    data = {"results": results, "reachable": reachable}
    _store("ports", data)
    return jsonify(data)


@app.route("/api/recommendations", methods=["GET"])
def api_recommendations():
    engine = RecommendationEngine()
    recs = engine.generate(
        network=_get("network"),
        ping_results=(_get("ping") or {}).get("results"),
        dns_results=(_get("dns") or {}).get("results"),
        cdn_results=(_get("cdn") or {}).get("results"),
        protocol_results=(_get("protocol") or {}).get("results"),
        port_results=(_get("ports") or {}).get("results"),
    )
    _store("recommendations", recs)
    return jsonify({"recommendations": recs})


@app.route("/api/architecture", methods=["GET"])
def api_architecture():
    builder = ArchitectureBuilder()
    arch = builder.build(
        network=_get("network"),
        ping_results=(_get("ping") or {}).get("results"),
        dns_results=(_get("dns") or {}).get("results"),
        cdn_results=(_get("cdn") or {}).get("results"),
        protocol_results=(_get("protocol") or {}).get("results"),
        port_results=(_get("ports") or {}).get("results"),
    )
    _store("architecture", arch)
    return jsonify(arch)


@app.route("/api/config", methods=["GET"])
def api_config():
    gen = ConfigGenerator()
    config = gen.generate(
        network=_get("network"),
        architecture=_get("architecture"),
        port_results=(_get("ports") or {}).get("results"),
    )
    _store("config", config)
    return jsonify(config)


@app.route("/api/report", methods=["GET"])
def api_report():
    """Return full report combining all available results."""
    return jsonify({
        "network": _get("network"),
        "ping": _get("ping"),
        "dns": _get("dns"),
        "cdn": _get("cdn"),
        "protocol": _get("protocol"),
        "ports": _get("ports"),
        "recommendations": _get("recommendations"),
        "architecture": _get("architecture"),
        "config": _get("config"),
        "generated_at": time.time(),
    })


@app.route("/api/report/export", methods=["GET"])
def api_report_export():
    """Export full report as downloadable JSON."""
    report = {
        "network": _get("network"),
        "ping": _get("ping"),
        "dns": _get("dns"),
        "cdn": _get("cdn"),
        "protocol": _get("protocol"),
        "ports": _get("ports"),
        "recommendations": _get("recommendations"),
        "architecture": _get("architecture"),
        "config": _get("config"),
        "generated_at": time.time(),
    }
    response = app.response_class(
        response=json.dumps(report, indent=2, ensure_ascii=False),
        status=200,
        mimetype="application/json",
    )
    response.headers["Content-Disposition"] = "attachment; filename=network_report.json"
    return response


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Network Optimizer Pro")
    parser.add_argument("--port", type=int, default=5000, help="Port to listen on")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--restricted", action="store_true", help="Enable restricted network mode")
    args = parser.parse_args()

    global _restricted_mode
    _restricted_mode = args.restricted

    logger.info("Starting Network Optimizer Pro on http://%s:%s", args.host, args.port)
    logger.info("Restricted mode: %s", _restricted_mode)
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
