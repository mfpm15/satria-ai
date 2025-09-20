# SATRIA AI User Guide 🚀

## Selamat Datang di SATRIA AI v2.0 Enterprise Edition!

SATRIA AI (Smart Autonomous Threat Response & Intelligence Agent) adalah platform cybersecurity berbasis AI yang dirancang untuk memberikan perlindungan proaktif, deteksi ancaman real-time, dan respons otomatis terhadap insiden keamanan.

---

## 🎯 Apa itu SATRIA AI?

SATRIA AI adalah sistem cybersecurity AI agentic yang dapat:

- **🔍 Mendeteksi Ancaman**: Menganalisis aktivitas mencurigakan secara real-time
- **🛡️ Respons Otomatis**: Mengambil tindakan pencegahan secara otomatis
- **📊 Intelligence Gathering**: Mengumpulkan dan menganalisis threat intelligence
- **🎭 Purple Team Validation**: Menjalankan simulasi serangan untuk validasi keamanan
- **📈 Compliance Monitoring**: Memantau dan melaporkan kepatuhan regulasi
- **👔 Executive Reporting**: Dashboard khusus untuk level C-suite

---

## 🚀 Cara Memulai

### 1. Akses SATRIA AI

**Untuk Development/Testing:**
```bash
# Clone repository
git clone https://github.com/mfpm15/satria-ai.git
cd satria-ai

# Setup environment
cp .env.example .env
# Edit .env file dengan konfigurasi Anda

# Install dependencies
poetry install

# Jalankan aplikasi
poetry run uvicorn satria.api.main:app --host 0.0.0.0 --port 8000 --reload
```

**Untuk Enterprise Deployment:**
```bash
# Setup enterprise dengan satu command
./scripts/enterprise_setup.sh
```

### 2. Konfigurasi Awal

1. **Set OpenRouter API Key** di file `.env`:
   ```bash
   OPENROUTER_API_KEY=your-api-key-here
   ```

2. **Konfigurasi Database** (opsional, sudah ada default):
   ```bash
   DATABASE_URL=postgresql://user:password@localhost:5432/satria_db
   ```

3. **Setup Redis** (opsional, sudah ada default):
   ```bash
   REDIS_URL=redis://localhost:6379/0
   ```

### 3. Akses Platform

- **API Endpoint**: `http://localhost:8000/api/v1/`
- **Health Check**: `http://localhost:8000/health`
- **API Documentation**: `http://localhost:8000/docs`

---

## 🔧 Cara Menggunakan SATRIA AI

### 1. 🤖 Menjalankan AI Agents

**a) Threat Detection Agent**
```python
import asyncio
from satria.agents.intelligence import ThreatIntelligenceAgent

async def run_threat_detection():
    agent = ThreatIntelligenceAgent()

    # Analisis file atau URL
    result = await agent.analyze_threat({
        "type": "url",
        "value": "http://suspicious-domain.com",
        "source": "user_report"
    })

    print(f"Threat Score: {result.confidence}")
    print(f"Risk Level: {result.risk_level}")

# Jalankan
asyncio.run(run_threat_detection())
```

**b) Behavioral Anomaly Detection**
```python
from satria.agents.intelligence import BehavioralAnomalyDetector

async def detect_anomalies():
    detector = BehavioralAnomalyDetector()

    # Monitor aktivitas sistem
    await detector.monitor_system_activity()

    # Dapatkan anomali yang terdeteksi
    anomalies = detector.get_detected_anomalies()

    for anomaly in anomalies:
        print(f"Anomaly: {anomaly.description}")
        print(f"Severity: {anomaly.severity}")

asyncio.run(detect_anomalies())
```

### 2. 🌐 Menggunakan REST API

**a) Submit Threat untuk Analisis**
```bash
curl -X POST "http://localhost:8000/api/v1/threats/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "hash",
    "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "source": "endpoint_detection"
  }'
```

**b) Dapatkan Status Agents**
```bash
curl -X GET "http://localhost:8000/api/v1/agents/status"
```

**c) Trigger Incident Response**
```bash
curl -X POST "http://localhost:8000/api/v1/incidents/respond" \
  -H "Content-Type: application/json" \
  -d '{
    "incident_id": "INC-001",
    "severity": "high",
    "type": "malware_detection"
  }'
```

### 3. 🎭 Purple Team Exercises

**a) Buat Exercise Baru**
```bash
curl -X POST "http://localhost:8000/api/v1/purple-team/exercises" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Phishing Simulation",
    "type": "technical",
    "scenario_id": "phishing_campaign",
    "start_time": "2024-01-20T10:00:00Z",
    "objectives": [
      {
        "id": "obj-001",
        "description": "Detect phishing email within 30 seconds",
        "success_criteria": ["Email blocked", "Alert generated"]
      }
    ]
  }'
```

**b) Mulai Exercise**
```bash
curl -X POST "http://localhost:8000/api/v1/purple-team/exercises/{exercise_id}/start"
```

### 4. 📊 Enterprise Compliance

**a) Dapatkan Compliance Status**
```bash
curl -X GET "http://localhost:8000/api/v1/enterprise/compliance/status"
```

**b) Generate Compliance Report**
```bash
curl -X POST "http://localhost:8000/api/v1/enterprise/compliance/reports" \
  -H "Content-Type: application/json" \
  -d '{
    "framework": "SOC2",
    "period_start": "2024-01-01",
    "period_end": "2024-01-31",
    "report_type": "assessment"
  }'
```

### 5. 👔 Executive Dashboards

**a) CEO Dashboard**
```bash
curl -X GET "http://localhost:8000/api/v1/enterprise/reporting/ceo"
```

**b) CISO Dashboard**
```bash
curl -X GET "http://localhost:8000/api/v1/enterprise/reporting/ciso"
```

---

## 📱 Contoh Use Cases

### Use Case 1: Deteksi Malware Otomatis

```python
# 1. Upload file untuk analisis
async def analyze_suspicious_file():
    from satria.agents.intelligence import ThreatIntelligenceAgent

    agent = ThreatIntelligenceAgent()

    # Analisis file hash
    result = await agent.analyze_threat({
        "type": "hash",
        "value": "malicious_file_hash_here",
        "source": "endpoint_detection",
        "metadata": {
            "filename": "suspicious.exe",
            "file_size": 1024000,
            "first_seen": "2024-01-20T10:00:00Z"
        }
    })

    if result.confidence > 0.8:
        print("🚨 MALWARE DETECTED!")
        print(f"Threat Type: {result.threat_type}")
        print(f"Confidence: {result.confidence * 100}%")

        # Trigger respons otomatis
        await agent.trigger_incident_response({
            "threat_id": result.threat_id,
            "actions": ["quarantine", "notify_admin", "block_hash"]
        })
```

### Use Case 2: Monitoring Anomali Network

```python
# 2. Monitor traffic anomali
async def monitor_network_anomalies():
    from satria.agents.intelligence import BehavioralAnomalyDetector

    detector = BehavioralAnomalyDetector()

    # Setup monitoring
    await detector.configure_monitoring({
        "network_interfaces": ["eth0", "wlan0"],
        "thresholds": {
            "bandwidth_spike": 0.9,
            "connection_count": 1000,
            "unusual_ports": [1337, 4444, 31337]
        }
    })

    # Start monitoring
    await detector.start_monitoring()

    # Process alerts
    while True:
        alerts = await detector.get_pending_alerts()

        for alert in alerts:
            if alert.severity == "high":
                print(f"🔥 Critical Anomaly: {alert.description}")

                # Auto-response
                await detector.respond_to_anomaly(alert)
```

### Use Case 3: Purple Team Exercise

```python
# 3. Jalankan Purple Team Exercise
async def run_purple_team_exercise():
    from satria.enterprise.purple_team import exercise_manager

    # Buat exercise
    exercise_data = {
        "name": "Advanced Persistent Threat Simulation",
        "type": "technical",
        "scenario_id": "apt_simulation",
        "start_time": "2024-01-20T14:00:00Z",
        "objectives": [
            {
                "id": "lateral-movement",
                "description": "Detect lateral movement within 15 minutes",
                "success_criteria": ["Network segmentation blocks movement", "SIEM alerts generated"]
            }
        ],
        "red_team": ["red-team-lead", "penetration-tester"],
        "blue_team": ["soc-analyst-1", "incident-responder"]
    }

    exercise_id = await exercise_manager.create_exercise(exercise_data)

    # Mulai exercise
    await exercise_manager.start_exercise(exercise_id)

    # Monitor progress
    while True:
        status = exercise_manager.get_exercise_status(exercise_id)

        if status["status"] == "completed":
            print("✅ Exercise completed!")

            # Generate report
            report = await exercise_manager.complete_exercise(exercise_id)
            print(f"Overall Score: {report['objectives']['completion_rate']}%")
            break

        await asyncio.sleep(30)  # Check every 30 seconds
```

### Use Case 4: Compliance Monitoring

```python
# 4. Monitor compliance real-time
async def monitor_compliance():
    from satria.enterprise.compliance import compliance_engine

    # Setup compliance monitoring
    compliance_engine.load_frameworks()

    # Assess current compliance
    soc2_assessment = await compliance_engine.assess_compliance("SOC2")
    gdpr_assessment = await compliance_engine.assess_compliance("GDPR")

    print(f"SOC2 Compliance Score: {soc2_assessment['score']}%")
    print(f"GDPR Compliance Score: {gdpr_assessment['score']}%")

    # Generate executive report
    report = await compliance_engine.generate_report({
        "framework": "SOC2",
        "period_start": datetime.now() - timedelta(days=30),
        "period_end": datetime.now(),
        "report_type": "executive_summary"
    })

    print(f"Report ID: {report['report_id']}")
    print(f"Executive Summary: {report['executive_summary']}")
```

---

## 🔧 Konfigurasi Lanjutan

### 1. AI Model Configuration

```python
# config/ai_models.yaml
ai_models:
  threat_analysis:
    provider: "openrouter"
    model: "anthropic/claude-3-sonnet"
    temperature: 0.1
    max_tokens: 4000

  incident_response:
    provider: "openrouter"
    model: "anthropic/claude-3-haiku"
    temperature: 0.0
    max_tokens: 2000

  behavioral_analysis:
    provider: "local"
    model: "xgboost_anomaly_detector"
    threshold: 0.85
```

### 2. Custom Alert Rules

```yaml
# config/alert_rules.yaml
alert_rules:
  - name: "Critical Malware Detection"
    condition: "threat_score > 0.9 AND threat_type == 'malware'"
    actions:
      - "quarantine_file"
      - "notify_soc"
      - "update_threat_intel"

  - name: "Unusual Login Activity"
    condition: "failed_logins > 5 AND source_ip NOT IN whitelist"
    actions:
      - "temporary_ip_block"
      - "notify_user"
      - "log_security_event"
```

### 3. Integration dengan SIEM

```python
# Integration dengan Splunk
from satria.integrations.siem import SplunkConnector

connector = SplunkConnector({
    "host": "splunk.company.com",
    "port": 8089,
    "username": "satria_service",
    "password": "secure_password"
})

# Send events ke Splunk
await connector.send_event({
    "source": "satria_ai",
    "sourcetype": "threat_detection",
    "event": {
        "threat_id": "THR-001",
        "severity": "high",
        "description": "Malware detected on endpoint"
    }
})
```

---

## 📊 Monitoring dan Analytics

### 1. Performance Metrics

SATRIA AI menyediakan metrics berikut:

- **Detection Rate**: Persentase ancaman yang berhasil dideteksi
- **False Positive Rate**: Tingkat alarm palsu
- **Response Time**: Waktu respons dari deteksi hingga mitigasi
- **Threat Intelligence Accuracy**: Akurasi prediksi threat intelligence
- **System Performance**: CPU, Memory, Network usage

### 2. Dashboard Monitoring

Akses dashboard monitoring di:
- **Grafana**: `http://localhost:3000` (untuk enterprise deployment)
- **Built-in Dashboard**: `http://localhost:8000/dashboard`

### 3. Alerting

Setup alerting untuk:
- High-severity threats detected
- System performance issues
- Compliance violations
- Failed purple team exercises

---

## 🔐 Security Best Practices

### 1. API Security

```python
# Gunakan API key untuk autentikasi
headers = {
    "Authorization": "Bearer your-api-key",
    "Content-Type": "application/json"
}

response = requests.post(
    "http://localhost:8000/api/v1/threats/analyze",
    headers=headers,
    json=threat_data
)
```

### 2. Data Protection

- Semua data sensitif dienkripsi at-rest dan in-transit
- API keys dan secrets disimpan dengan encryption
- Audit logging untuk semua aktivitas

### 3. Network Security

```yaml
# docker-compose.yml untuk production
networks:
  satria-internal:
    internal: true
  satria-external:
    driver: bridge
```

---

## 🚨 Troubleshooting

### 1. Common Issues

**Q: API tidak merespons**
```bash
# Check service status
curl http://localhost:8000/health

# Check logs
poetry run python -c "from satria.core.logger import logger; logger.info('Health check')"
```

**Q: AI model tidak berfungsi**
```bash
# Verify API key
echo $OPENROUTER_API_KEY

# Test connection
curl -H "Authorization: Bearer $OPENROUTER_API_KEY" https://openrouter.ai/api/v1/models
```

**Q: Database connection error**
```bash
# Check PostgreSQL
pg_isready -h localhost -p 5432

# Test connection
python -c "import psycopg2; conn = psycopg2.connect('postgresql://user:pass@localhost:5432/db')"
```

### 2. Debug Mode

```bash
# Run dengan debug logging
export LOG_LEVEL=DEBUG
poetry run uvicorn satria.api.main:app --reload --log-level debug
```

### 3. Performance Tuning

```python
# config/performance.yaml
performance:
  max_concurrent_analyses: 10
  cache_ttl: 3600
  batch_size: 100
  worker_processes: 4
```

---

## 📚 API Reference

### 1. Core Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/api/v1/agents/status` | Agent status |
| POST | `/api/v1/threats/analyze` | Analyze threat |
| GET | `/api/v1/threats/{threat_id}` | Get threat details |
| POST | `/api/v1/incidents/respond` | Trigger incident response |

### 2. Enterprise Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/enterprise/compliance/status` | Compliance status |
| POST | `/api/v1/enterprise/compliance/reports` | Generate compliance report |
| GET | `/api/v1/enterprise/reporting/ceo` | CEO dashboard |
| GET | `/api/v1/enterprise/reporting/ciso` | CISO dashboard |

### 3. Purple Team Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/purple-team/exercises` | Create exercise |
| POST | `/api/v1/purple-team/exercises/{id}/start` | Start exercise |
| GET | `/api/v1/purple-team/exercises/{id}/status` | Exercise status |
| POST | `/api/v1/purple-team/exercises/{id}/complete` | Complete exercise |

---

## 🎓 Learning Resources

### 1. Tutorials
- [Getting Started with SATRIA AI](docs/tutorials/getting-started.md)
- [Building Custom Agents](docs/tutorials/custom-agents.md)
- [Purple Team Exercises](docs/tutorials/purple-team.md)
- [Enterprise Deployment](docs/tutorials/enterprise-deployment.md)

### 2. Examples
- [Example Threat Analysis Scripts](examples/threat-analysis/)
- [Custom Integration Examples](examples/integrations/)
- [Purple Team Scenarios](examples/purple-team/)

### 3. API Documentation
- [Interactive API Docs](http://localhost:8000/docs)
- [ReDoc API Documentation](http://localhost:8000/redoc)

---

## 🤝 Support dan Community

### 1. Getting Help

- **Documentation**: [docs.satria-ai.com](docs/README.md)
- **GitHub Issues**: [Report bugs or request features](https://github.com/mfpm15/satria-ai/issues)
- **Email Support**: Hubungi developer untuk enterprise support

### 2. Contributing

Kami menerima kontribusi! Silakan:
1. Fork repository
2. Buat feature branch
3. Submit pull request

### 3. Enterprise Support

Untuk enterprise support dan custom development:
- **Professional Services**: Implementation dan training
- **24/7 Support**: Critical issue response
- **Custom Development**: Feature development sesuai kebutuhan

---

## 🚀 What's Next?

SATRIA AI terus berkembang dengan fitur-fitur baru:

### Phase 5 (Coming Soon):
- **Quantum-Enhanced AI**: Quantum computing untuk threat analysis
- **Global Threat Intelligence Network**: Threat sharing antar organisasi
- **Advanced ML Models**: Self-learning behavioral analysis
- **IoT Security**: Specialized IoT device protection
- **Zero Trust Architecture**: Complete zero trust implementation

### Stay Updated:
- Follow repository untuk updates
- Join beta testing program
- Subscribe to newsletter untuk announcement

---

**Selamat menggunakan SATRIA AI! 🚀🛡️**

*"Protecting the digital world with intelligent, autonomous cybersecurity."*