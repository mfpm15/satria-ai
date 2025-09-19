# SATRIA AI - Autonomous Cybersecurity Agentic System

🛡️ **S**mart **A**utonomous **T**hreat **R**esponse & **I**ntelligence **A**gent

SATRIA adalah sistem AI cybersecurity yang menggabungkan red team dan blue team capabilities dengan Quantum Decision Engine (QDE) untuk response otomatis terhadap ancaman cyber.

## 🏗️ Arsitektur System

### Core Components
- **Quantum Decision Engine (QDE)**: Algoritma probabilistic superposition untuk memilih persona red/blue team
- **Consciousness Layer**: Menyatukan alert, threat intelligence, dan memory untuk pembelajaran otomatis
- **Action Orchestrator**: Mengubah insight menjadi tindakan nyata (bukan hanya rekomendasi)

### 54 AI Agents dalam 6 Layer:
1. **Perception & Sensing** (12 agents) - Data collection & normalization
2. **Context & Understanding** (10 agents) - Analysis & correlation
3. **Memory & Learning** (5 agents) - Incident memory & pattern learning
4. **Decision & Planning** (5 agents) - Response planning dengan QDE
5. **Action & Orchestration** (8 agents) - Automated response execution
6. **Governance & Compliance** (14 agents) - Audit, compliance & explainability

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- Docker & Docker Compose
- 16GB+ RAM recommended

### Installation
```bash
git clone https://github.com/your-org/satria-ai.git
cd satria-ai
make setup
make run
```

### Access Points
- **API Gateway**: http://localhost:8001
- **API Documentation**: http://localhost:8001/docs
- **Health Check**: http://localhost:8001/health

## 📋 Development Roadmap

### Phase 1: Foundation (Bulan 1-6)
- [x] Event Bus & OCSF schema
- [x] Context Graph (Neo4j)
- [x] Basic QDE implementation
- [ ] 5 priority agents (Log Collector, EDR Connector, Risk Scoring, Triage Planner, EDR Orchestrator)

### Phase 2: Intelligence (Bulan 7-12) ✅ COMPLETED
- [x] Behavioral Anomaly Detector with ML models
- [x] Network Anomaly Detector with graph analysis
- [x] Threat Intelligence Engine (MISP/OpenCTI integration)
- [x] Incident Memory System with vector embeddings
- [x] Analyst Copilot with natural language interface

### Phase 3: Orchestration (Bulan 13-18)
- [ ] Multi-vendor orchestrators
- [ ] Forensic capabilities
- [ ] Advanced QDE personas

### Phase 4: Enterprise (Bulan 19-24)
- [ ] Compliance mapping
- [ ] Purple team validation
- [ ] Executive reporting

## 🛠️ Technology Stack

- **Runtime**: Python 3.11 + AsyncIO
- **Event Bus**: Apache Kafka
- **Graph DB**: Neo4j
- **Vector Store**: Chroma
- **LLM**: Ollama (Local deployment)
- **Container**: Docker + Kubernetes
- **Monitoring**: Prometheus + Grafana

## 📝 Event Schema Example

```json
{
  "event_type": "webshell_detection",
  "entity_ids": {"host":"WEB-01","site":"coffee.lab","ip":"192.168.77.123"},
  "attack_tags": ["T1505.003","T1190"],
  "risk": 88, "confidence": 0.93,
  "evidence": ["/var/www/html/wp-content/uploads/shell.php"],
  "recommendations": [
    {"op":"waf.rule.push","rule_id":"block-php-uploads","ttl":"24h"},
    {"op":"edr.quarantine_proc","host":"WEB-01","proc":"php-fpm"}
  ]
}
```

## 🤝 Contributing

1. Fork repository
2. Create feature branch: `git checkout -b feature/agent-name`
3. Follow coding standards dalam `/docs/development-guide.md`
4. Submit pull request

## 📄 License

MIT License - See [LICENSE](LICENSE) file

## 🔗 Links

- [Documentation](docs/)
- [API Reference](docs/api/)
- [Agent Development Guide](docs/agents/)
- [Deployment Guide](docs/deployment/)

---
🇮🇩 **Made with ❤️ for Indonesian Cybersecurity Community**