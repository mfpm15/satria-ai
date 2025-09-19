#!/usr/bin/env python3
"""
Test script for OpenRouter LLM integration
"""

import asyncio
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from satria.core.llm_client import llm_client, LLMMessage


async def test_openrouter_integration():
    """Test OpenRouter LLM integration"""
    print("🚀 Testing SATRIA AI OpenRouter Integration")
    print("=" * 50)

    try:
        # Initialize LLM client
        print("1. Initializing OpenRouter client...")
        success = await llm_client.initialize()
        if not success:
            print("❌ Failed to initialize LLM client")
            return False

        print("✅ OpenRouter client initialized successfully")

        # Test basic chat completion
        print("\n2. Testing basic chat completion...")
        messages = [
            LLMMessage(role="system", content="You are SATRIA AI, a cybersecurity assistant."),
            LLMMessage(role="user", content="What is a SQL injection attack? Give a brief explanation.")
        ]

        response = await llm_client.chat_completion(
            messages=messages,
            max_tokens=150,
            temperature=0.7
        )

        print(f"✅ Chat completion successful")
        print(f"   Model: {response.model}")
        print(f"   Tokens used: {response.tokens_used}")
        print(f"   Latency: {response.latency_ms:.2f}ms")
        print(f"   Confidence: {response.confidence:.2f}")
        print(f"   Response: {response.content[:100]}...")

        # Test security event analysis
        print("\n3. Testing security event analysis...")
        event_data = {
            "event_type": "authentication_failure",
            "risk": 75,
            "message": "Multiple failed login attempts detected",
            "entity_ids": {"user": "admin", "source_ip": "192.168.1.100"},
            "enrichment": {
                "failed_attempts": 15,
                "time_window": "5 minutes",
                "source_country": "Unknown"
            }
        }

        analysis_response = await llm_client.analyze_security_event(event_data)
        print(f"✅ Security event analysis successful")
        print(f"   Analysis length: {len(analysis_response.content)} characters")
        print(f"   Confidence: {analysis_response.confidence:.2f}")
        print(f"   Analysis preview: {analysis_response.content[:200]}...")

        # Test incident response plan generation
        print("\n4. Testing incident response plan generation...")
        ir_response = await llm_client.generate_incident_response_plan(
            incident_description="Ransomware attack detected on file server",
            severity="critical",
            affected_systems=["file-server-01", "backup-server-01"]
        )

        print(f"✅ Incident response plan generated successfully")
        print(f"   Plan length: {len(ir_response.content)} characters")
        print(f"   Confidence: {ir_response.confidence:.2f}")
        print(f"   Plan preview: {ir_response.content[:200]}...")

        # Test metrics
        print("\n5. Checking LLM client metrics...")
        metrics = llm_client.get_metrics()
        print(f"✅ Metrics retrieved:")
        for key, value in metrics.items():
            print(f"   {key}: {value}")

        print("\n🎉 All OpenRouter integration tests passed!")
        return True

    except Exception as e:
        print(f"❌ Error during testing: {e}")
        import traceback
        traceback.print_exc()
        return False

    finally:
        # Cleanup
        await llm_client.cleanup()


if __name__ == "__main__":
    # Run the test
    result = asyncio.run(test_openrouter_integration())
    exit(0 if result else 1)