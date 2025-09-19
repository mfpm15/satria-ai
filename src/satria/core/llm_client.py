"""
SATRIA AI - LLM Client for OpenRouter.ai Integration
Provides unified interface for AI/LLM operations
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any, AsyncGenerator
from dataclasses import dataclass
import time

from openai import OpenAI, AsyncOpenAI
from satria.core.config import settings


@dataclass
class LLMResponse:
    """LLM Response data structure"""
    content: str
    model: str
    tokens_used: int
    latency_ms: float
    confidence: float = 0.0
    metadata: Dict[str, Any] = None


@dataclass
class LLMMessage:
    """LLM Message structure"""
    role: str  # system, user, assistant
    content: str
    metadata: Optional[Dict[str, Any]] = None


class OpenRouterClient:
    """OpenRouter.ai LLM Client for SATRIA AI"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.client: Optional[AsyncOpenAI] = None
        self.sync_client: Optional[OpenAI] = None
        self.requests_count = 0
        self.total_tokens = 0
        self.errors_count = 0

    async def initialize(self) -> bool:
        """Initialize OpenRouter client"""
        try:
            # Initialize async client
            self.client = AsyncOpenAI(
                base_url=settings.openrouter_base_url,
                api_key=settings.openrouter_api_key
            )

            # Initialize sync client for non-async operations
            self.sync_client = OpenAI(
                base_url=settings.openrouter_base_url,
                api_key=settings.openrouter_api_key
            )

            # Test connection
            await self._test_connection()

            self.logger.info("OpenRouter client initialized successfully")
            return True

        except Exception as e:
            self.logger.error(f"Failed to initialize OpenRouter client: {e}")
            return False

    async def _test_connection(self):
        """Test OpenRouter connection"""
        try:
            response = await self.client.chat.completions.create(
                model=settings.openrouter_model,
                messages=[{"role": "user", "content": "Hello, test connection"}],
                max_tokens=10,
                extra_headers={
                    "HTTP-Referer": settings.openrouter_site_url,
                    "X-Title": settings.openrouter_site_name,
                }
            )
            self.logger.info("OpenRouter connection test successful")
            return True

        except Exception as e:
            self.logger.error(f"OpenRouter connection test failed: {e}")
            raise

    async def chat_completion(
        self,
        messages: List[LLMMessage],
        model: Optional[str] = None,
        max_tokens: int = 2048,
        temperature: float = 0.7,
        stream: bool = False,
        **kwargs
    ) -> LLMResponse:
        """Generate chat completion using OpenRouter"""
        start_time = time.time()

        try:
            # Convert LLMMessage to OpenAI format
            openai_messages = [
                {"role": msg.role, "content": msg.content}
                for msg in messages
            ]

            # Prepare request
            request_params = {
                "model": model or settings.openrouter_model,
                "messages": openai_messages,
                "max_tokens": max_tokens,
                "temperature": temperature,
                "extra_headers": {
                    "HTTP-Referer": settings.openrouter_site_url,
                    "X-Title": settings.openrouter_site_name,
                },
                **kwargs
            }

            # Make request
            response = await self.client.chat.completions.create(**request_params)

            # Calculate metrics
            latency_ms = (time.time() - start_time) * 1000
            tokens_used = response.usage.total_tokens if response.usage else 0

            # Update statistics
            self.requests_count += 1
            self.total_tokens += tokens_used

            # Extract content
            content = response.choices[0].message.content if response.choices else ""

            # Calculate confidence based on response quality
            confidence = self._calculate_confidence(content, tokens_used)

            return LLMResponse(
                content=content,
                model=response.model,
                tokens_used=tokens_used,
                latency_ms=latency_ms,
                confidence=confidence,
                metadata={
                    "finish_reason": response.choices[0].finish_reason if response.choices else None,
                    "usage": response.usage.model_dump() if response.usage else None
                }
            )

        except Exception as e:
            self.errors_count += 1
            self.logger.error(f"LLM chat completion error: {e}")
            raise

    async def stream_completion(
        self,
        messages: List[LLMMessage],
        model: Optional[str] = None,
        max_tokens: int = 2048,
        temperature: float = 0.7,
        **kwargs
    ) -> AsyncGenerator[str, None]:
        """Stream chat completion"""
        try:
            openai_messages = [
                {"role": msg.role, "content": msg.content}
                for msg in messages
            ]

            stream = await self.client.chat.completions.create(
                model=model or settings.openrouter_model,
                messages=openai_messages,
                max_tokens=max_tokens,
                temperature=temperature,
                stream=True,
                extra_headers={
                    "HTTP-Referer": settings.openrouter_site_url,
                    "X-Title": settings.openrouter_site_name,
                },
                **kwargs
            )

            async for chunk in stream:
                if chunk.choices and chunk.choices[0].delta.content:
                    yield chunk.choices[0].delta.content

        except Exception as e:
            self.logger.error(f"LLM stream completion error: {e}")
            raise

    async def analyze_security_event(self, event_data: Dict[str, Any]) -> LLMResponse:
        """Analyze security event using LLM"""
        system_prompt = """You are SATRIA AI, an advanced cybersecurity AI assistant.
        Analyze the provided security event and provide:
        1. Risk assessment (1-100 scale)
        2. Threat classification
        3. Recommended actions
        4. MITRE ATT&CK technique mapping if applicable

        Be concise but thorough in your analysis."""

        user_prompt = f"""Analyze this security event:

        Event Type: {event_data.get('event_type', 'Unknown')}
        Risk Score: {event_data.get('risk', 0)}
        Message: {event_data.get('message', '')}
        Entities: {event_data.get('entity_ids', {})}
        Enrichment: {event_data.get('enrichment', {})}

        Provide your analysis in a structured format."""

        messages = [
            LLMMessage(role="system", content=system_prompt),
            LLMMessage(role="user", content=user_prompt)
        ]

        return await self.chat_completion(messages, temperature=0.3)

    async def generate_incident_response_plan(
        self,
        incident_description: str,
        severity: str = "medium",
        affected_systems: List[str] = None
    ) -> LLMResponse:
        """Generate incident response plan"""
        system_prompt = """You are SATRIA AI's incident response specialist.
        Generate a comprehensive incident response plan with:
        1. Immediate containment steps
        2. Investigation procedures
        3. Eradication actions
        4. Recovery steps
        5. Lessons learned capture

        Format as actionable steps with priorities."""

        user_prompt = f"""Generate an incident response plan for:

        Incident: {incident_description}
        Severity: {severity}
        Affected Systems: {affected_systems or ['Not specified']}

        Provide a structured response plan with clear priorities."""

        messages = [
            LLMMessage(role="system", content=system_prompt),
            LLMMessage(role="user", content=user_prompt)
        ]

        return await self.chat_completion(messages, temperature=0.4)

    async def threat_intelligence_analysis(
        self,
        indicators: List[str],
        context: Dict[str, Any] = None
    ) -> LLMResponse:
        """Analyze threat intelligence indicators"""
        system_prompt = """You are SATRIA AI's threat intelligence analyst.
        Analyze the provided indicators and provide:
        1. Threat actor attribution possibilities
        2. Campaign or malware family associations
        3. Recommended monitoring and detection strategies
        4. Contextual threat landscape information

        Base analysis on known threat intelligence patterns."""

        user_prompt = f"""Analyze these threat indicators:

        Indicators: {indicators}
        Context: {context or {}}

        Provide threat intelligence analysis with actionable insights."""

        messages = [
            LLMMessage(role="system", content=system_prompt),
            LLMMessage(role="user", content=user_prompt)
        ]

        return await self.chat_completion(messages, temperature=0.3)

    async def generate_detection_rules(
        self,
        attack_scenario: str,
        rule_format: str = "sigma"
    ) -> LLMResponse:
        """Generate detection rules for attack scenarios"""
        system_prompt = f"""You are SATRIA AI's detection engineering specialist.
        Generate {rule_format} detection rules for the given attack scenario.

        Include:
        1. Rule logic with proper syntax
        2. False positive considerations
        3. Tuning recommendations
        4. MITRE ATT&CK mapping

        Ensure rules are production-ready and well-documented."""

        user_prompt = f"""Generate {rule_format} detection rules for:

        Attack Scenario: {attack_scenario}

        Provide complete, tested detection rules with documentation."""

        messages = [
            LLMMessage(role="system", content=system_prompt),
            LLMMessage(role="user", content=user_prompt)
        ]

        return await self.chat_completion(messages, temperature=0.2)

    def _calculate_confidence(self, content: str, tokens_used: int) -> float:
        """Calculate confidence score for LLM response"""
        confidence = 0.5  # Base confidence

        # Length-based confidence
        if len(content) > 100:
            confidence += 0.2
        if len(content) > 500:
            confidence += 0.1

        # Token efficiency
        if tokens_used > 50:
            confidence += 0.1

        # Content quality indicators
        quality_indicators = [
            "mitre", "att&ck", "cve-", "ioc", "indicator",
            "recommendation", "action", "step", "procedure"
        ]

        content_lower = content.lower()
        quality_score = sum(1 for indicator in quality_indicators if indicator in content_lower)
        confidence += min(quality_score * 0.05, 0.2)

        return min(confidence, 1.0)

    def get_metrics(self) -> Dict[str, Any]:
        """Get LLM client metrics"""
        return {
            "requests_count": self.requests_count,
            "total_tokens": self.total_tokens,
            "errors_count": self.errors_count,
            "error_rate": self.errors_count / max(self.requests_count, 1),
            "avg_tokens_per_request": self.total_tokens / max(self.requests_count, 1),
            "model": settings.openrouter_model,
            "base_url": settings.openrouter_base_url
        }

    async def cleanup(self):
        """Cleanup resources"""
        try:
            if self.client:
                await self.client.close()
            self.logger.info("OpenRouter client cleanup completed")
        except Exception as e:
            self.logger.error(f"Error during LLM client cleanup: {e}")


# Global LLM client instance
llm_client = OpenRouterClient()