# 🚀 SATRIA AI Quick Start Guide

## Cara Menjalankan SATRIA AI v2.0

### 1. **Start Server**

```bash
cd satria-ai
PYTHONPATH=/home/terrestrial/Desktop/satria-ai/src poetry run uvicorn satria.api.main:app --host 0.0.0.0 --port 8000 --reload
```

### 2. **Akses Web Interface**

Buka browser dan kunjungi:

**🌐 Chat Interface**: http://localhost:8000/interface/

### 3. **Contoh Penggunaan**

Di web interface, coba masukkan permintaan seperti:

#### 🔍 **Red Team (Reconnaissance)**
```
cek IP di website google.com
scan port pada domain facebook.com
vulnerability assessment website example.com
```

#### 🛡️ **Blue Team (Defense)**
```
analisis ancaman domain suspicious.com
monitor anomali pada network 192.168.1.1
incident response untuk malware detected
cek reputation IP 8.8.8.8
```

#### 🟣 **Purple Team (Collaborative)**
```
purple team analysis pada target.com
comprehensive security assessment example.com
```

### 4. **Fitur Web Interface**

- **Chat Interface**: Input permintaan cybersecurity dan dapatkan response dari AI
- **Team Auto-Selection**: AI akan otomatis memilih team (Red/Blue/Purple) berdasarkan permintaan
- **Real-time Execution**: Lihat hasil analisis secara real-time
- **Artifacts**: Download hasil scan, analysis reports, dll
- **History**: Lihat riwayat percakapan dan analisis

### 5. **Examples dalam Action**

#### Example 1: DNS Reconnaissance
**Input**: `cek IP di google.com`

**Response**:
```
🔍 Red Team Reconnaissance - google.com

DNS Information:
- A: 142.250.190.14, 142.250.190.46
- AAAA: 2404:6800:4003:c00::65

Artifacts: dns_records.json
```

#### Example 2: Threat Analysis
**Input**: `analisis ancaman domain malicious-site.com`

**Response**:
```
🛡️ Blue Team Threat Analysis - malicious-site.com

Threat Assessment:
- Risk Level: HIGH
- Confidence: 89%
- Threat Type: malicious_domain

Indicators of Compromise (IoCs):
- Domain: malicious-site.com (confidence: 89%)
- IP: 192.168.1.100 (confidence: 76%)
```

### 6. **API Documentation**

Jika ingin menggunakan API langsung:

**📖 Interactive API Docs**: http://localhost:8000/docs
**📚 ReDoc**: http://localhost:8000/redoc

### 7. **REST API Examples**

```bash
# Health Check
curl http://localhost:8000/health

# Chat API
curl -X POST "http://localhost:8000/interface/chat" \
  -F "user_input=cek IP di google.com"

# Agent Status
curl http://localhost:8000/api/v1/agents/status
```

### 8. **Troubleshooting**

**Error**: Import errors atau module not found
**Solution**: Pastikan `PYTHONPATH` di-set dengan benar

**Error**: Service connection failed
**Solution**: Services seperti Kafka, Neo4j bersifat optional dan tidak mempengaruhi web interface

**Error**: OpenRouter API error
**Solution**: Set OpenRouter API key di `.env` file untuk fitur AI yang optimal

---

## 🎯 **Ready to Use!**

SATRIA AI v2.0 dengan web interface sekarang siap digunakan untuk:

✅ **DNS Reconnaissance & Port Scanning**
✅ **Threat Intelligence & Analysis**
✅ **Network Monitoring & Anomaly Detection**
✅ **Vulnerability Assessment**
✅ **Incident Response Planning**
✅ **Purple Team Collaboration**

**Happy Cybersecurity Operations! 🛡️✨**