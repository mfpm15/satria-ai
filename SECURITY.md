# Security Policy

## 🔒 Security Overview

SATRIA AI takes security seriously. This document outlines our security practices and guidelines for secure deployment and operation.

## 🚨 Security Alert - API Key Exposure

**IMMEDIATE ACTION REQUIRED:** An OpenRouter API key was previously exposed in the public repository. The following actions have been taken:

### Actions Completed:
1. ✅ Removed hardcoded API key from `src/satria/core/config.py`
2. ✅ Updated configuration to use environment variables only
3. ✅ Enhanced `.env.example` with proper security guidance
4. ✅ Verified `.gitignore` includes sensitive files

### Required Actions for Users:
1. **Generate new OpenRouter API key** at https://openrouter.ai/keys
2. **Add the new key to your `.env` file**:
   ```bash
   OPENROUTER_API_KEY=your-new-api-key-here
   ```
3. **Never commit `.env` file to repository**

## 🛡️ Security Configuration

### Environment Variables Security

**NEVER** commit the following files:
- `.env` - Contains sensitive configuration
- Any files containing API keys, passwords, or secrets
- Database connection strings with credentials
- TLS certificates and private keys

### Required Security Settings

```env
# Strong secret key for JWT tokens
SECRET_KEY=your-crypto-strong-secret-key-minimum-32-chars

# OpenRouter API Key (REQUIRED)
OPENROUTER_API_KEY=your-openrouter-api-key

# Database credentials
POSTGRES_URL=postgresql://user:password@host:port/database
NEO4J_URL=bolt://user:password@host:port
REDIS_URL=redis://host:port/db

# External service credentials
CROWDSTRIKE_CLIENT_ID=your-crowdstrike-id
CROWDSTRIKE_CLIENT_SECRET=your-crowdstrike-secret
```

## 🔐 Secure Deployment

### Development Environment
1. Copy `.env.example` to `.env`
2. Fill in all required credentials
3. Use strong, unique passwords
4. Enable DEBUG=false for any external access

### Production Environment
1. Use environment variables or secure secret management
2. Enable HTTPS with valid TLS certificates
3. Configure proper firewall rules
4. Use encrypted connections for all external services
5. Enable audit logging
6. Set `IMMUTABLE_STORAGE_ENABLED=true`

### Docker Security
```yaml
# docker-compose.yml security practices
services:
  satria-api:
    environment:
      - DEBUG=false
      - ENVIRONMENT=production
    secrets:
      - openrouter_api_key
      - postgres_password

secrets:
  openrouter_api_key:
    external: true
  postgres_password:
    external: true
```

## 🚨 Incident Response

### If API Keys Are Exposed:
1. **Immediately rotate** the exposed keys
2. **Update all applications** using the old keys
3. **Review access logs** for unauthorized usage
4. **Report to security team** if enterprise deployment

### If Security Vulnerability Found:
1. **Do not** create public GitHub issues
2. **Email security concerns** to: security@your-org.com
3. **Include detailed description** and reproduction steps

## 🔍 Security Monitoring

SATRIA AI includes built-in security monitoring:

### Automatic Security Features:
- API rate limiting
- Authentication token expiration
- Audit logging for all security events
- Encrypted communication with external services
- Input validation and sanitization

### Monitoring Alerts:
- Failed authentication attempts
- Unusual API usage patterns
- Configuration changes
- External service connection failures

## 📋 Security Checklist

### Pre-deployment:
- [ ] All API keys stored in environment variables
- [ ] No hardcoded credentials in code
- [ ] Strong passwords for all services
- [ ] TLS enabled for all external connections
- [ ] Firewall configured properly
- [ ] Debug mode disabled in production
- [ ] Security logging enabled

### Regular Security Maintenance:
- [ ] Rotate API keys quarterly
- [ ] Update dependencies regularly
- [ ] Review access logs monthly
- [ ] Test backup and recovery procedures
- [ ] Monitor for security advisories
- [ ] Audit user access permissions

## 🔧 Security Tools Integration

### Supported Security Platforms:
- **EDR**: CrowdStrike, SentinelOne, Microsoft Defender
- **SIEM**: Splunk, Elastic, IBM QRadar, Azure Sentinel
- **Cloud Security**: AWS Security Hub, Azure Security Center, GCP Security Command
- **Threat Intelligence**: MISP, OpenCTI
- **Vulnerability Scanning**: Integrated scanners

### Security API Endpoints:
```
GET /api/v1/security/status - Security health check
GET /api/v1/security/metrics - Security metrics
POST /api/v1/security/incident - Report security incident
GET /api/v1/security/audit - Audit log access
```

## 🚀 Security Best Practices

### Code Security:
- All inputs validated and sanitized
- SQL injection prevention via parameterized queries
- XSS protection with output encoding
- CSRF protection enabled
- Secure random number generation for tokens

### Infrastructure Security:
- Network segmentation between services
- Least privilege access principles
- Regular security patches and updates
- Encrypted data at rest and in transit
- Multi-factor authentication where possible

### Operational Security:
- Regular security assessments
- Incident response procedures
- Security awareness training
- Secure development lifecycle (SDLC)
- Threat modeling for new features

## 📞 Contact

For security-related questions or concerns:
- **Security Email**: security@your-org.com
- **GitHub Security Advisories**: Use private vulnerability reporting
- **Emergency Contact**: +1-XXX-XXX-XXXX (24/7 security hotline)

---

**⚠️ Remember: Security is everyone's responsibility. When in doubt, ask for help!**