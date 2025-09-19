# SATRIA AI API Examples & Usage Guide

This guide provides practical examples of how to use the SATRIA AI API for common cybersecurity workflows.

## 🔧 Setup & Authentication

### Basic Setup
```bash
export SATRIA_API_URL="http://localhost:8001"
export SATRIA_API_TOKEN="your-bearer-token-here"
```

### Python Client Setup
```python
import requests
import json
from datetime import datetime, timedelta

class SatriaClient:
    def __init__(self, base_url="http://localhost:8001", token=None):
        self.base_url = base_url
        self.headers = {
            "Content-Type": "application/json"
        }
        if token:
            self.headers["Authorization"] = f"Bearer {token}"

    def get(self, endpoint):
        return requests.get(f"{self.base_url}{endpoint}", headers=self.headers)

    def post(self, endpoint, data):
        return requests.post(f"{self.base_url}{endpoint}",
                           headers=self.headers,
                           json=data)

# Initialize client
client = SatriaClient(token="your-token")
```

## 🏥 Health & System Monitoring

### Basic Health Check
```bash
curl http://localhost:8001/health
```

```python
# Check system health
response = client.get("/health")
if response.status_code == 200:
    health = response.json()
    print(f"System Status: {health['status']}")
    print(f"Version: {health['version']}")
    print(f"Uptime: {health.get('uptime_seconds', 0)} seconds")
```

### Detailed System Status
```bash
curl -H "Authorization: Bearer your-token" \
     http://localhost:8001/health/detailed
```

```python
# Get detailed system metrics
response = client.get("/health/detailed")
if response.status_code == 200:
    details = response.json()
    print(f"Event Bus Status: {details['components']['event_bus']['status']}")
    print(f"Events Published: {details['components']['event_bus']['metrics']['events_published']}")
    print(f"QDE Decisions: {details['components']['qde']['metrics']['decisions_count']}")
```

## 🧠 Intelligence System Examples

### 1. System Status Monitoring
```python
def monitor_intelligence_system():
    """Monitor the intelligence system health and metrics"""
    response = client.get("/v2/intelligence/system-status")

    if response.status_code == 200:
        status = response.json()

        print(f"Overall Health: {status['overall_health']}")
        print(f"Healthy Agents: {status['healthy_agents']}/{status['total_agents']}")

        # Intelligence metrics
        metrics = status['intelligence_metrics']
        print(f"Events Processed: {metrics['total_events_processed']}")
        print(f"Anomalies Detected: {metrics['anomalies_detected']}")
        print(f"Memories Stored: {metrics['memories_stored']}")

        # Check individual agents
        for agent, stats in status['agents_status'].items():
            print(f"\n{agent.replace('_', ' ').title()}:")
            for metric, value in stats.items():
                print(f"  {metric}: {value}")

    return status
```

### 2. User Anomaly Analysis
```python
def analyze_user_behavior(user_email, hours=24):
    """Analyze user behavior for anomalies"""
    data = {
        "entity_type": "user",
        "entity_id": user_email,
        "time_window_hours": hours,
        "include_behavioral": True,
        "include_network": True
    }

    response = client.post("/v2/intelligence/anomaly-analysis", data)

    if response.status_code == 200:
        analysis = response.json()

        print(f"Analysis for {user_email}:")
        print(f"Overall Risk Score: {analysis['overall_risk_score']}/100")

        # Behavioral analysis
        behavioral = analysis['behavioral_analysis']
        print(f"Behavioral Status: {behavioral['status']}")
        print(f"Anomalies Detected: {behavioral['anomalies_detected']}")

        # Network analysis
        network = analysis['network_analysis']
        print(f"Network Flows Analyzed: {network['flows_analyzed']}")
        print(f"Network Anomalies: {network['anomalies_detected']}")

        # Detailed anomalies
        for anomaly in analysis.get('anomalies_detected', []):
            print(f"\n⚠️ {anomaly['type']}:")
            print(f"   Confidence: {anomaly['confidence']:.2f}")
            print(f"   Details: {anomaly['details']}")

    return analysis

# Example usage
analysis = analyze_user_behavior("john.doe@company.com", hours=24)
```

### 3. Threat Intelligence Lookup
```python
def threat_intel_lookup(indicators):
    """Perform threat intelligence lookup on indicators"""
    data = {
        "indicators": indicators,
        "indicator_types": ["ip", "domain", "hash"],
        "include_context": True
    }

    response = client.post("/v2/intelligence/threat-intel", data)

    if response.status_code == 200:
        results = response.json()

        print(f"Analyzed {results['indicators_analyzed']} indicators")

        for result in results['enrichment_results']:
            indicator = result['indicator']
            threat_score = result['threat_score']

            print(f"\n🔍 {indicator}:")
            print(f"   Threat Score: {threat_score}/100")

            if threat_score > 50:
                print("   ⚠️ HIGH RISK INDICATOR")
                print(f"   Sources: {', '.join(result['sources'])}")
                print(f"   Tags: {', '.join(result['tags'])}")
                print(f"   Last Seen: {result['last_seen']}")

    return results

# Example usage
suspicious_indicators = [
    "192.168.1.100",
    "malicious-domain.com",
    "e3b0c44298fc1c149afbf4c8996fb924"
]
intel_results = threat_intel_lookup(suspicious_indicators)
```

## 💭 Memory System Examples

### 1. Query Incident Memory
```python
def query_incident_memory(query, limit=10):
    """Query the incident memory system"""
    data = {
        "query": query,
        "limit": limit,
        "similarity_threshold": 0.7
    }

    response = client.post("/v2/memory/query", data)

    if response.status_code == 200:
        results = response.json()

        print(f"Found {results['insights_found']} similar incidents:")

        for insight in results['insights']:
            print(f"\n📋 Incident {insight['incident_id']}:")
            print(f"   Similarity: {insight['similarity_score']:.2f}")
            print(f"   Description: {insight['description']}")
            print(f"   Timestamp: {insight['timestamp']}")

            print("   Lessons Learned:")
            for lesson in insight['lessons_learned']:
                print(f"   - {lesson}")

    return results

# Example queries
lateral_movement = query_incident_memory("Show me similar incidents involving lateral movement")
phishing_attacks = query_incident_memory("Recent phishing campaigns with email attachments")
ransomware_cases = query_incident_memory("Ransomware incidents in the last 6 months")
```

## 🤖 Analyst Copilot Examples

### 1. Create Copilot Session
```python
def create_copilot_session():
    """Create a new analyst copilot session"""
    data = {
        "preferences": {
            "response_format": "technical_details",
            "include_mitre_mapping": True,
            "language": "en"
        }
    }

    response = client.post("/v2/copilot/session", data)

    if response.status_code == 200:
        session = response.json()
        print(f"Created session: {session['session_id']}")
        return session['session_id']

    return None
```

### 2. Query Copilot
```python
def ask_copilot(query, session_id=None, query_type="threat_analysis"):
    """Ask the analyst copilot a question"""
    data = {
        "query": query,
        "query_type": query_type,
        "context": {
            "severity": "high"
        },
        "preferred_format": "technical_details"
    }

    if session_id:
        data["session_id"] = session_id

    response = client.post("/v2/copilot/query", data)

    if response.status_code == 200:
        result = response.json()

        print(f"Query ID: {result['query_id']}")
        print(f"Confidence: {result['response']['confidence']:.2f}")
        print(f"Processing Time: {result['processing_time']}s")

        print(f"\n🤖 Response:")
        print(result['response']['text'])

        print(f"\n📋 Recommendations:")
        for rec in result['response']['recommendations']:
            print(f"- {rec}")

        print(f"\n❓ Follow-up Questions:")
        for question in result['response']['follow_up_questions']:
            print(f"- {question}")

        print(f"\n📚 Supporting Evidence:")
        for evidence in result['response']['supporting_evidence']:
            print(f"- {evidence}")

    return result

# Example usage
session_id = create_copilot_session()
apt29_analysis = ask_copilot(
    "What are the most effective indicators for detecting APT29?",
    session_id=session_id,
    query_type="threat_analysis"
)
```

## 🔄 Workflow Examples

### 1. Complete Threat Hunting Workflow
```python
def threat_hunting_workflow(user_email, suspicious_ip):
    """Complete threat hunting workflow"""
    print(f"🔍 Starting threat hunt for {user_email} and {suspicious_ip}")

    # Step 1: Analyze user behavior
    print("\n1. Analyzing user behavior...")
    user_analysis = analyze_user_behavior(user_email)

    # Step 2: Check threat intelligence
    print("\n2. Checking threat intelligence...")
    intel_results = threat_intel_lookup([suspicious_ip])

    # Step 3: Query similar incidents
    print("\n3. Searching for similar incidents...")
    similar_incidents = query_incident_memory(
        f"Incidents involving user {user_email} or IP {suspicious_ip}"
    )

    # Step 4: Ask copilot for analysis
    print("\n4. Getting AI analysis...")
    copilot_response = ask_copilot(
        f"Analyze this threat scenario: User {user_email} connecting to {suspicious_ip}. "
        f"User risk score: {user_analysis['overall_risk_score']}. "
        f"IP threat score: {intel_results['enrichment_results'][0]['threat_score']}."
    )

    # Step 5: Generate summary
    print("\n📊 THREAT HUNT SUMMARY:")
    print(f"User Risk: {user_analysis['overall_risk_score']}/100")
    print(f"IP Threat Score: {intel_results['enrichment_results'][0]['threat_score']}/100")
    print(f"Similar Incidents: {similar_incidents['insights_found']}")
    print(f"AI Confidence: {copilot_response['response']['confidence']:.2f}")

# Example usage
threat_hunting_workflow("suspicious.user@company.com", "185.220.101.182")
```

### 2. Incident Response Workflow
```python
def incident_response_workflow(incident_description):
    """Automated incident response workflow"""
    print(f"🚨 Incident Response: {incident_description}")

    # Step 1: Query memory for similar incidents
    similar = query_incident_memory(incident_description)

    # Step 2: Get copilot recommendations
    response = ask_copilot(
        f"I have this security incident: {incident_description}. "
        f"Based on similar incidents and best practices, what are the immediate response steps?",
        query_type="incident_response"
    )

    # Step 3: Monitor system status
    system_status = monitor_intelligence_system()

    print("\n📋 INCIDENT RESPONSE PLAN:")
    for rec in response['response']['recommendations']:
        print(f"✓ {rec}")

    if similar['insights_found'] > 0:
        print(f"\n📚 Lessons from {similar['insights_found']} similar incidents:")
        for insight in similar['insights'][:3]:  # Top 3 similar
            for lesson in insight['lessons_learned']:
                print(f"- {lesson}")

# Example usage
incident_response_workflow("Ransomware encryption detected on file server")
```

### 3. Daily Security Monitoring
```python
def daily_security_check():
    """Daily security monitoring routine"""
    print("🛡️ Daily Security Check - " + datetime.now().strftime("%Y-%m-%d %H:%M"))

    # System health
    print("\n1. System Health Check:")
    health = client.get("/health/detailed").json()
    if health['status'] == 'healthy':
        print("✅ All systems operational")
    else:
        print("❌ System issues detected")

    # Intelligence system status
    print("\n2. Intelligence System Status:")
    intel_status = client.get("/v2/intelligence/system-status").json()
    print(f"Healthy Agents: {intel_status['healthy_agents']}/{intel_status['total_agents']}")

    # Performance metrics
    print("\n3. Performance Metrics:")
    perf = client.get("/v2/intelligence/performance").json()
    metrics = perf['performance_metrics']
    print(f"Anomalies Detected: {metrics['anomaly_detection']['total_anomalies']}")
    print(f"Threat Intel Hit Rate: {metrics['threat_intelligence']['hit_rate']:.2%}")
    print(f"Active Copilot Sessions: {metrics['analyst_copilot']['active_sessions']}")

    # Ask copilot for daily summary
    daily_summary = ask_copilot(
        "Provide a summary of today's security posture and any recommended actions",
        query_type="security_summary"
    )

    print("\n📊 Daily Security Summary:")
    print(daily_summary['response']['text'])

# Schedule this to run daily
daily_security_check()
```

## 🚨 Error Handling

### Robust Error Handling
```python
class SatriaAPIError(Exception):
    """Custom exception for SATRIA API errors"""
    pass

def safe_api_call(func, *args, **kwargs):
    """Wrapper for safe API calls with error handling"""
    try:
        response = func(*args, **kwargs)

        if response.status_code == 200:
            return response.json()
        elif response.status_code == 401:
            raise SatriaAPIError("Authentication failed - check your token")
        elif response.status_code == 429:
            raise SatriaAPIError("Rate limit exceeded - please wait")
        elif response.status_code >= 500:
            raise SatriaAPIError(f"Server error: {response.status_code}")
        else:
            raise SatriaAPIError(f"API error: {response.status_code} - {response.text}")

    except requests.exceptions.ConnectionError:
        raise SatriaAPIError("Cannot connect to SATRIA API - check if server is running")
    except requests.exceptions.Timeout:
        raise SatriaAPIError("API request timed out")
    except Exception as e:
        raise SatriaAPIError(f"Unexpected error: {str(e)}")

# Example usage with error handling
try:
    results = safe_api_call(client.get, "/v2/intelligence/system-status")
    print("System status retrieved successfully")
except SatriaAPIError as e:
    print(f"API Error: {e}")
```

## 📊 Performance Monitoring

### API Performance Monitoring
```python
import time
from contextlib import contextmanager

@contextmanager
def api_timer(operation_name):
    """Context manager to time API operations"""
    start_time = time.time()
    try:
        yield
    finally:
        elapsed = time.time() - start_time
        print(f"⏱️ {operation_name} took {elapsed:.2f} seconds")

# Example usage
with api_timer("Anomaly Analysis"):
    analysis = analyze_user_behavior("test.user@company.com")

with api_timer("Threat Intelligence Lookup"):
    intel = threat_intel_lookup(["192.168.1.100"])
```

## 🔗 Integration Examples

### Slack Integration
```python
import slack_sdk

def send_alert_to_slack(webhook_url, message):
    """Send security alert to Slack"""
    slack_data = {
        "text": f"🚨 SATRIA AI Security Alert",
        "attachments": [
            {
                "color": "danger",
                "fields": [
                    {
                        "title": "Alert Details",
                        "value": message,
                        "short": False
                    }
                ]
            }
        ]
    }

    response = requests.post(webhook_url, json=slack_data)
    return response.status_code == 200

# Example usage
def monitor_and_alert():
    intel_status = client.get("/v2/intelligence/system-status").json()

    if intel_status['overall_health'] != 'healthy':
        send_alert_to_slack(
            "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK",
            f"SATRIA AI system health degraded: {intel_status['healthy_agents']}/{intel_status['total_agents']} agents healthy"
        )
```

---

*For more examples and advanced usage, see the [complete API documentation](API_DOCUMENTATION.md)*