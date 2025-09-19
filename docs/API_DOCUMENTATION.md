# SATRIA AI API v2.0 - Complete Documentation

## Overview

SATRIA AI (Smart Autonomous Threat Response & Intelligence Agent) is an advanced cybersecurity platform that provides autonomous threat detection, response, and intelligence analysis capabilities.

**Base URL**: `http://localhost:8001`
**Version**: 2.0.0
**Environment**: Development

## Authentication

All API endpoints (except health checks) require authentication using Bearer tokens.

```bash
Authorization: Bearer <your-token-here>
```

## API Endpoints

### 🏥 Health & System Status

#### GET /health
Basic health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-09-19T13:47:44.374007",
  "version": "0.1.0",
  "environment": "development"
}
```

#### GET /health/detailed
Comprehensive system health with component details.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-09-19T13:47:55.785092",
  "uptime_seconds": 23,
  "components": {
    "event_bus": {
      "status": "healthy",
      "metrics": {
        "events_published": 0,
        "events_consumed": 0,
        "errors": 0,
        "last_activity": null,
        "active_consumers": 0,
        "registered_handlers": 0,
        "routing_rules": 0
      }
    },
    "context_graph": {
      "status": "healthy"
    },
    "qde": {
      "status": "healthy",
      "metrics": {
        "decisions_count": 0
      }
    }
  }
}
```

---

## 🧠 Phase 2: Intelligence Endpoints

### Intelligence System Status

#### GET /v2/intelligence/system-status
Get comprehensive intelligence system status.

**Headers:**
```
Authorization: Bearer <token>
```

**Response:**
```json
{
  "overall_health": "healthy",
  "healthy_agents": 5,
  "total_agents": 5,
  "intelligence_metrics": {
    "total_events_processed": 1250,
    "anomalies_detected": 15,
    "memories_stored": 45,
    "copilot_queries": 12
  },
  "agents_status": {
    "behavioral_anomaly_detector": {
      "events_processed": 500,
      "anomalies_detected": 8,
      "behavioral_profiles": 25,
      "active_models": 3
    },
    "network_anomaly_detector": {
      "flows_processed": 750,
      "anomalies_detected": 7,
      "beacon_candidates": 2
    },
    "threat_intelligence_engine": {
      "enrichment_requests": 200,
      "hit_rate": 0.85,
      "cached_indicators": 150
    },
    "incident_memory_system": {
      "memories_stored": 45,
      "patterns_learned": 12,
      "insights_generated": 8
    },
    "analyst_copilot": {
      "queries_processed": 12,
      "active_sessions": 2,
      "avg_response_time": 1.2
    }
  },
  "status_timestamp": "2025-09-19T13:30:00.000Z"
}
```

### Anomaly Analysis

#### POST /v2/intelligence/anomaly-analysis
Perform comprehensive anomaly analysis on an entity.

**Headers:**
```
Authorization: Bearer <token>
Content-Type: application/json
```

**Request Body:**
```json
{
  "entity_type": "user",
  "entity_id": "john.doe@company.com",
  "time_window_hours": 24,
  "include_behavioral": true,
  "include_network": true
}
```

**Response:**
```json
{
  "entity_type": "user",
  "entity_id": "john.doe@company.com",
  "analysis_timestamp": "2025-09-19T13:30:00.000Z",
  "behavioral_analysis": {
    "status": "healthy",
    "profiles_analyzed": 1,
    "anomalies_detected": 2,
    "active_models": 3
  },
  "network_analysis": {
    "status": "healthy",
    "flows_analyzed": 156,
    "anomalies_detected": 1,
    "beacon_candidates": 0
  },
  "overall_risk_score": 35,
  "anomalies_detected": [
    {
      "type": "unusual_login_time",
      "confidence": 0.85,
      "details": "Login at 2:30 AM outside normal hours"
    }
  ]
}
```

### Threat Intelligence

#### POST /v2/intelligence/threat-intel
Perform threat intelligence lookup on indicators.

**Headers:**
```
Authorization: Bearer <token>
Content-Type: application/json
```

**Request Body:**
```json
{
  "indicators": [
    "192.168.1.100",
    "malicious-domain.com",
    "e3b0c44298fc1c149afbf4c8996fb924"
  ],
  "indicator_types": ["ip", "domain", "hash"],
  "include_context": true
}
```

**Response:**
```json
{
  "indicators_analyzed": 3,
  "enrichment_results": [
    {
      "indicator": "192.168.1.100",
      "threat_score": 0,
      "sources": [],
      "last_seen": null,
      "tags": []
    },
    {
      "indicator": "malicious-domain.com",
      "threat_score": 85,
      "sources": ["MISP", "OpenCTI"],
      "last_seen": "2025-09-18T10:30:00.000Z",
      "tags": ["malware", "c2"]
    }
  ],
  "threat_intel_stats": {
    "requests_processed": 1250,
    "hit_rate": 0.15,
    "cached_indicators": 450
  },
  "analysis_timestamp": "2025-09-19T13:30:00.000Z"
}
```

### Memory System

#### POST /v2/memory/query
Query the incident memory system using natural language.

**Headers:**
```
Authorization: Bearer <token>
Content-Type: application/json
```

**Request Body:**
```json
{
  "query": "Show me similar incidents involving lateral movement",
  "limit": 10,
  "similarity_threshold": 0.7
}
```

**Response:**
```json
{
  "query": "Show me similar incidents involving lateral movement",
  "insights_found": 3,
  "insights": [
    {
      "incident_id": "INC-2025-001",
      "similarity_score": 0.92,
      "description": "Lateral movement detected via SMB",
      "timestamp": "2025-09-15T14:20:00.000Z",
      "lessons_learned": [
        "Disable unnecessary SMB shares",
        "Monitor east-west traffic"
      ]
    }
  ],
  "memory_stats": {
    "total_memories": 45,
    "patterns_learned": 12,
    "insights_generated": 8
  },
  "query_timestamp": "2025-09-19T13:30:00.000Z"
}
```

### Analyst Copilot

#### POST /v2/copilot/query
Query the AI analyst copilot for assistance.

**Headers:**
```
Authorization: Bearer <token>
Content-Type: application/json
```

**Request Body:**
```json
{
  "query": "What are the most effective indicators for detecting APT29?",
  "query_type": "threat_analysis",
  "context": {
    "incident_id": "INC-2025-002",
    "severity": "high"
  },
  "preferred_format": "technical_details",
  "session_id": "session-123"
}
```

**Response:**
```json
{
  "query_id": "query_20250919133000",
  "response": {
    "text": "APT29 detection indicators include: 1) PowerShell execution with encoded commands, 2) WMI persistence mechanisms, 3) Cobalt Strike beacon traffic patterns...",
    "confidence": 0.95,
    "recommendations": [
      "Monitor PowerShell execution logs",
      "Implement WMI monitoring",
      "Deploy network traffic analysis"
    ],
    "follow_up_questions": [
      "Would you like specific YARA rules for APT29?",
      "Should I provide Sigma detection rules?"
    ],
    "supporting_evidence": [
      "MITRE ATT&CK: T1059.001",
      "Recent threat intelligence reports"
    ],
    "data_sources": [
      "MITRE ATT&CK",
      "Internal threat intelligence",
      "Historical incident data"
    ]
  },
  "processing_time": 1.2,
  "timestamp": "2025-09-19T13:30:00.000Z"
}
```

#### POST /v2/copilot/session
Create a new analyst copilot session.

**Headers:**
```
Authorization: Bearer <token>
Content-Type: application/json
```

**Request Body:**
```json
{
  "preferences": {
    "response_format": "technical_details",
    "include_mitre_mapping": true,
    "language": "en"
  }
}
```

**Response:**
```json
{
  "session_id": "session-456",
  "analyst_id": "analyst_123",
  "created_at": "2025-09-19T13:30:00.000Z",
  "status": "active"
}
```

#### DELETE /v2/copilot/session/{session_id}
End an analyst copilot session.

**Headers:**
```
Authorization: Bearer <token>
```

**Response:**
```json
{
  "session_id": "session-456",
  "status": "ended",
  "ended_at": "2025-09-19T13:45:00.000Z"
}
```

### Performance Metrics

#### GET /v2/intelligence/performance
Get intelligence system performance metrics.

**Headers:**
```
Authorization: Bearer <token>
```

**Response:**
```json
{
  "performance_metrics": {
    "anomaly_detection": {
      "behavioral_events_processed": 500,
      "network_flows_processed": 750,
      "total_anomalies": 15
    },
    "threat_intelligence": {
      "enrichment_requests": 200,
      "hit_rate": 0.85,
      "api_errors": 2
    },
    "memory_system": {
      "memories_stored": 45,
      "patterns_learned": 12,
      "insights_generated": 8
    },
    "analyst_copilot": {
      "queries_processed": 12,
      "active_sessions": 2,
      "avg_response_time": 1.2
    }
  },
  "collection_timestamp": "2025-09-19T13:30:00.000Z",
  "system_version": "SATRIA AI v2.0 - Intelligence Phase"
}
```

---

## 📝 Phase 1: Foundation Endpoints

### Event Processing

#### POST /v1/events/ingest
Ingest security events into the system.

#### GET /v1/events/{event_id}
Retrieve specific event details.

### Risk Scoring

#### POST /v1/risk/score
Calculate risk score for an event or entity.

### Triage & Response

#### GET /v1/triage/cases
List active triage cases.

#### POST /v1/triage/cases/{case_id}/action
Execute response action on a triage case.

---

## 🔒 Security Considerations

1. **Authentication**: All endpoints require valid Bearer tokens
2. **Rate Limiting**: API calls are rate-limited to prevent abuse
3. **Input Validation**: All inputs are validated and sanitized
4. **Audit Logging**: All API calls are logged for security auditing

## 📊 Response Codes

- `200 OK`: Successful request
- `201 Created`: Resource created successfully
- `400 Bad Request`: Invalid request parameters
- `401 Unauthorized`: Missing or invalid authentication
- `403 Forbidden`: Insufficient permissions
- `404 Not Found`: Resource not found
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server error

## 🚀 Getting Started

1. **Start the server**:
```bash
poetry run uvicorn satria.api.main:app --host 0.0.0.0 --port 8001 --reload
```

2. **Check system health**:
```bash
curl http://localhost:8001/health
```

3. **View API documentation**:
Open `http://localhost:8001/docs` in your browser

4. **Authenticate and test**:
```bash
curl -H "Authorization: Bearer your-token" \
     http://localhost:8001/v2/intelligence/system-status
```

## 🔗 Additional Resources

- **Interactive API Docs**: http://localhost:8001/docs
- **OpenAPI Schema**: http://localhost:8001/openapi.json
- **GitHub Repository**: [Coming Soon]
- **CI/CD Pipeline**: [Coming Soon]

---

*Generated by SATRIA AI Documentation System*
*Last Updated: 2025-09-19*