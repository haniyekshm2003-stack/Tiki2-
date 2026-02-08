# 🌐 Network Optimizer Pro

**Advanced, professional, modular network analysis and optimization toolkit.**

A local web dashboard application that performs deep network analysis from your real internet connection — not from cloud servers. All tests run locally to give you accurate results for your specific network conditions.

## ✨ Features

### 🌐 Network Scanner
- Public/local IP detection with ISP info
- Latency, jitter, packet loss measurement
- TCP and UDP connectivity testing
- Download throughput estimation
- MTU and fragmentation detection
- NAT type detection
- Connection stability scoring
- Async/parallel test execution

### 📍 Global Ping Test
- Latency testing to servers across 15+ countries
- Region-based ranking (Europe, Asia, North America, etc.)
- Best location recommendations for VPS/VPN/Proxy
- Sortable tables and charts

### 🧠 DNS Analysis
- Benchmark 13+ public DNS servers
- Custom DNS server testing
- Response time, reliability, and error rate measurement
- DNS ranking and comparison charts
- History tracking

### ☁️ CDN Testing
- Test 10+ CDN edge networks
- Connect latency and download time measurement
- Stability scoring
- CDN comparison and ranking

### 🔎 Protocol Benchmark
- HTTP, HTTPS, TCP, UDP testing
- TLS handshake timing
- WebSocket connectivity testing
- Performance ranking by protocol

### 🔐 Port Scan
- Safe-mode port reachability scanning
- 20+ common ports tested
- Rate-limited, non-aggressive scanning
- Stability scoring per port

### 🧠 Smart Recommendations
- Best server location
- Best DNS server
- Best protocol category
- Best port range
- Best CDN
- Confidence scores for each recommendation

### ⚙️ Architecture Builder
- Recommended connection type
- Transport layer suggestion
- Encryption recommendation
- Tunnel category
- Port + protocol combinations
- Multi-level fallback plan

### 🧩 Config Generator
- Optimized MTU, timeout, retry parameters
- Keepalive and multiplexing settings
- Generic template config (software-independent)
- JSON export

### 🛡️ Restricted Network Mode
- Adaptive testing with rate limiting
- Low-risk scan methods
- Confidence scoring for results

## 🚀 Quick Start

### Prerequisites
- Python 3.10 or higher
- pip

### Installation

```bash
cd netoptimizer
pip install -r requirements.txt
```

### Run

```bash
python app.py
```

Then open **http://localhost:5000** in your browser.

### Options

```bash
python app.py --port 8080          # Custom port
python app.py --restricted         # Enable restricted network mode
python app.py --host 0.0.0.0      # Listen on all interfaces
```

## 🧪 Running Tests

```bash
cd netoptimizer
python -m pytest tests/ -v
```

## 📂 Project Structure

```
netoptimizer/
├── app.py                          # Flask web application
├── requirements.txt                # Python dependencies
├── modules/
│   ├── network_scanner.py          # Core network scanning engine
│   ├── ping_tester.py              # Global ping testing
│   ├── dns_analyzer.py             # DNS benchmarking
│   ├── cdn_tester.py               # CDN edge testing
│   ├── protocol_tester.py          # Protocol benchmarking
│   ├── port_scanner.py             # Port reachability scanning
│   ├── recommendation.py           # Smart recommendation engine
│   ├── architecture.py             # Service architecture builder
│   └── config_generator.py         # Config template generator
├── templates/
│   ├── base.html                   # Base layout template
│   ├── dashboard.html              # Main dashboard
│   ├── ping_test.html              # Global ping test page
│   ├── dns_test.html               # DNS analysis page
│   ├── cdn_test.html               # CDN test page
│   ├── protocol_test.html          # Protocol benchmark page
│   ├── port_scan.html              # Port scan page
│   ├── recommendations.html        # Recommendations page
│   ├── architecture.html           # Architecture builder page
│   └── report.html                 # Full report page
├── static/
│   ├── css/style.css               # Stylesheet
│   └── js/main.js                  # Frontend JavaScript
└── tests/
    ├── test_recommendation.py      # Recommendation engine tests
    ├── test_architecture.py        # Architecture builder tests
    ├── test_config_generator.py    # Config generator tests
    └── test_app.py                 # Flask API tests
```

## 🏗️ Architecture

- **Backend**: Python with Flask
- **Frontend**: HTML5/CSS3/JavaScript with Chart.js
- **Testing**: unittest / pytest
- **Design**: Modular, async-ready, extensible

## ⚠️ Important Notes

- All tests run from your local machine's real internet connection
- Port scanning is done in safe mode with rate limiting
- No aggressive or harmful scanning behavior
- The tool provides recommendations only — it does not bypass any restrictions
- No credentials or API keys are required to run

## 📄 License

MIT
