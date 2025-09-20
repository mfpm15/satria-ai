#!/usr/bin/env python3
"""
SATRIA AI Enterprise Health Check Script
Comprehensive health monitoring for enterprise deployment
"""

import os
import sys
import json
import time
import asyncio
import logging
from datetime import datetime
from typing import Dict, Any, List
import requests
import psycopg2
import redis

# Add src to path
sys.path.insert(0, '/app/src')

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class HealthChecker:
    def __init__(self):
        self.checks = []
        self.critical_checks = []
        self.warning_checks = []
        self.results = {}

    def add_check(self, name: str, check_func, critical: bool = True, timeout: int = 10):
        """Add a health check"""
        check = {
            'name': name,
            'func': check_func,
            'critical': critical,
            'timeout': timeout
        }
        self.checks.append(check)

        if critical:
            self.critical_checks.append(name)
        else:
            self.warning_checks.append(name)

    async def run_check(self, check: Dict[str, Any]) -> Dict[str, Any]:
        """Run a single health check with timeout"""
        start_time = time.time()

        try:
            # Run check with timeout
            if asyncio.iscoroutinefunction(check['func']):
                result = await asyncio.wait_for(
                    check['func'](),
                    timeout=check['timeout']
                )
            else:
                result = await asyncio.wait_for(
                    asyncio.to_thread(check['func']),
                    timeout=check['timeout']
                )

            duration = time.time() - start_time

            return {
                'status': 'healthy',
                'duration': round(duration, 3),
                'details': result if isinstance(result, dict) else {'message': str(result)}
            }

        except asyncio.TimeoutError:
            return {
                'status': 'timeout',
                'duration': check['timeout'],
                'details': {'error': f"Check timed out after {check['timeout']}s"}
            }

        except Exception as e:
            duration = time.time() - start_time
            return {
                'status': 'unhealthy',
                'duration': round(duration, 3),
                'details': {'error': str(e)}
            }

    async def run_all_checks(self) -> Dict[str, Any]:
        """Run all health checks"""
        logger.info("Starting health checks...")

        # Run checks concurrently
        tasks = []
        for check in self.checks:
            task = asyncio.create_task(self.run_check(check))
            tasks.append((check['name'], check['critical'], task))

        # Wait for all checks to complete
        for name, critical, task in tasks:
            result = await task
            self.results[name] = result

            # Log results
            status = result['status']
            duration = result['duration']

            if status == 'healthy':
                logger.info(f"✓ {name}: {status} ({duration}s)")
            elif status == 'timeout':
                logger.warning(f"⏱ {name}: {status} ({duration}s)")
            else:
                logger.error(f"✗ {name}: {status} ({duration}s) - {result['details'].get('error', '')}")

        return self.get_overall_status()

    def get_overall_status(self) -> Dict[str, Any]:
        """Calculate overall health status"""
        total_checks = len(self.checks)
        healthy_checks = len([r for r in self.results.values() if r['status'] == 'healthy'])
        critical_failures = len([
            name for name in self.critical_checks
            if self.results.get(name, {}).get('status') != 'healthy'
        ])
        warning_failures = len([
            name for name in self.warning_checks
            if self.results.get(name, {}).get('status') != 'healthy'
        ])

        # Determine overall status
        if critical_failures > 0:
            overall_status = 'critical'
        elif warning_failures > 0:
            overall_status = 'warning'
        else:
            overall_status = 'healthy'

        return {
            'timestamp': datetime.now().isoformat(),
            'overall_status': overall_status,
            'summary': {
                'total_checks': total_checks,
                'healthy_checks': healthy_checks,
                'critical_failures': critical_failures,
                'warning_failures': warning_failures
            },
            'checks': self.results
        }

# Health check functions
def check_application_startup():
    """Check if the application is responding"""
    try:
        response = requests.get(
            'http://localhost:8000/health',
            timeout=5,
            headers={'User-Agent': 'SATRIA-HealthCheck/1.0'}
        )

        if response.status_code == 200:
            data = response.json()
            return {
                'status_code': response.status_code,
                'response_time': response.elapsed.total_seconds(),
                'version': data.get('version', 'unknown')
            }
        else:
            raise Exception(f"HTTP {response.status_code}: {response.text}")

    except requests.exceptions.ConnectionError:
        raise Exception("Application not responding - connection refused")
    except Exception as e:
        raise Exception(f"Application health check failed: {str(e)}")

def check_database_connection():
    """Check database connectivity and basic operations"""
    try:
        database_url = os.environ['DATABASE_URL']

        # Test connection
        conn = psycopg2.connect(database_url)
        cursor = conn.cursor()

        # Test basic query
        cursor.execute("SELECT version(), current_timestamp;")
        result = cursor.fetchone()

        # Test table existence
        cursor.execute("""
            SELECT COUNT(*) FROM information_schema.tables
            WHERE table_schema = 'public';
        """)
        table_count = cursor.fetchone()[0]

        cursor.close()
        conn.close()

        return {
            'version': result[0] if result else 'unknown',
            'timestamp': result[1].isoformat() if result else 'unknown',
            'table_count': table_count
        }

    except Exception as e:
        raise Exception(f"Database connection failed: {str(e)}")

def check_redis_connection():
    """Check Redis connectivity and performance"""
    try:
        redis_url = os.environ['REDIS_URL']

        # Test connection
        r = redis.from_url(redis_url)

        # Test basic operations
        start_time = time.time()
        r.ping()
        ping_time = time.time() - start_time

        # Test read/write
        test_key = f"healthcheck:{int(time.time())}"
        r.setex(test_key, 10, "test_value")
        value = r.get(test_key)
        r.delete(test_key)

        if value != b"test_value":
            raise Exception("Redis read/write test failed")

        # Get info
        info = r.info()

        return {
            'ping_time': round(ping_time * 1000, 2),  # ms
            'connected_clients': info.get('connected_clients', 0),
            'used_memory_human': info.get('used_memory_human', 'unknown'),
            'uptime_in_seconds': info.get('uptime_in_seconds', 0)
        }

    except Exception as e:
        raise Exception(f"Redis connection failed: {str(e)}")

def check_disk_space():
    """Check available disk space"""
    try:
        import shutil

        # Check data directory
        data_usage = shutil.disk_usage('/app/data')
        log_usage = shutil.disk_usage('/app/logs')

        data_free_gb = data_usage.free / (1024**3)
        log_free_gb = log_usage.free / (1024**3)

        # Warning if less than 1GB free
        if data_free_gb < 1.0 or log_free_gb < 1.0:
            raise Exception(f"Low disk space: data={data_free_gb:.1f}GB, logs={log_free_gb:.1f}GB")

        return {
            'data_free_gb': round(data_free_gb, 2),
            'log_free_gb': round(log_free_gb, 2),
            'data_total_gb': round(data_usage.total / (1024**3), 2),
            'log_total_gb': round(log_usage.total / (1024**3), 2)
        }

    except Exception as e:
        raise Exception(f"Disk space check failed: {str(e)}")

def check_memory_usage():
    """Check memory usage"""
    try:
        import psutil

        # Get memory info
        memory = psutil.virtual_memory()

        # Warning if memory usage > 90%
        if memory.percent > 90:
            raise Exception(f"High memory usage: {memory.percent}%")

        return {
            'total_gb': round(memory.total / (1024**3), 2),
            'available_gb': round(memory.available / (1024**3), 2),
            'used_percent': memory.percent,
            'free_percent': round(100 - memory.percent, 1)
        }

    except ImportError:
        return {'message': 'psutil not available'}
    except Exception as e:
        raise Exception(f"Memory check failed: {str(e)}")

def check_environment_variables():
    """Check required environment variables"""
    required_vars = [
        'DATABASE_URL',
        'REDIS_URL',
        'OPENROUTER_API_KEY',
        'SECRET_KEY'
    ]

    missing_vars = []
    present_vars = []

    for var in required_vars:
        if var in os.environ and os.environ[var]:
            present_vars.append(var)
        else:
            missing_vars.append(var)

    if missing_vars:
        raise Exception(f"Missing environment variables: {', '.join(missing_vars)}")

    return {
        'required_count': len(required_vars),
        'present_count': len(present_vars),
        'present_vars': present_vars
    }

def check_api_endpoints():
    """Check critical API endpoints"""
    try:
        base_url = 'http://localhost:8000'
        endpoints = [
            '/health',
            '/api/v1/agents/status',
            '/api/v1/enterprise/compliance/status'
        ]

        results = {}

        for endpoint in endpoints:
            try:
                response = requests.get(
                    f"{base_url}{endpoint}",
                    timeout=5,
                    headers={'User-Agent': 'SATRIA-HealthCheck/1.0'}
                )
                results[endpoint] = {
                    'status_code': response.status_code,
                    'response_time_ms': round(response.elapsed.total_seconds() * 1000, 2)
                }
            except Exception as e:
                results[endpoint] = {
                    'error': str(e)
                }

        # Check if any critical endpoints failed
        failed_endpoints = [
            ep for ep, result in results.items()
            if 'error' in result or result.get('status_code', 0) >= 500
        ]

        if failed_endpoints:
            raise Exception(f"Failed endpoints: {', '.join(failed_endpoints)}")

        return results

    except Exception as e:
        raise Exception(f"API endpoints check failed: {str(e)}")

async def check_enterprise_modules():
    """Check enterprise module functionality"""
    try:
        # Import and test enterprise modules
        from satria.enterprise.compliance import compliance_engine
        from satria.enterprise.governance import governance_manager
        from satria.enterprise.purple_team import purple_team_validator

        results = {}

        # Test compliance engine
        try:
            status = compliance_engine.get_status()
            results['compliance'] = {
                'status': 'healthy',
                'frameworks_loaded': len(status.get('active_frameworks', []))
            }
        except Exception as e:
            results['compliance'] = {'status': 'error', 'error': str(e)}

        # Test governance manager
        try:
            status = governance_manager.get_status()
            results['governance'] = {
                'status': 'healthy',
                'policies_loaded': len(status.get('active_policies', []))
            }
        except Exception as e:
            results['governance'] = {'status': 'error', 'error': str(e)}

        # Test purple team validator
        try:
            status = purple_team_validator.get_status()
            results['purple_team'] = {
                'status': 'healthy',
                'scenarios_loaded': len(status.get('available_scenarios', []))
            }
        except Exception as e:
            results['purple_team'] = {'status': 'error', 'error': str(e)}

        # Check for any failures
        failed_modules = [
            module for module, result in results.items()
            if result.get('status') == 'error'
        ]

        if failed_modules:
            raise Exception(f"Failed modules: {', '.join(failed_modules)}")

        return results

    except Exception as e:
        raise Exception(f"Enterprise modules check failed: {str(e)}")

async def main():
    """Main health check function"""
    checker = HealthChecker()

    # Add all health checks
    checker.add_check('application', check_application_startup, critical=True, timeout=10)
    checker.add_check('database', check_database_connection, critical=True, timeout=15)
    checker.add_check('redis', check_redis_connection, critical=True, timeout=10)
    checker.add_check('environment', check_environment_variables, critical=True, timeout=5)
    checker.add_check('disk_space', check_disk_space, critical=False, timeout=5)
    checker.add_check('memory', check_memory_usage, critical=False, timeout=5)
    checker.add_check('api_endpoints', check_api_endpoints, critical=True, timeout=15)
    checker.add_check('enterprise_modules', check_enterprise_modules, critical=True, timeout=10)

    # Run all checks
    result = await checker.run_all_checks()

    # Output results
    print(json.dumps(result, indent=2))

    # Exit with appropriate code
    overall_status = result['overall_status']
    if overall_status == 'healthy':
        sys.exit(0)
    elif overall_status == 'warning':
        sys.exit(1)  # Warning but container should continue
    else:
        sys.exit(2)  # Critical failure

if __name__ == '__main__':
    asyncio.run(main())