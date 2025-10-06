import asyncio
import json
from typing import Optional, Dict, Any
from datetime import datetime

from .config import get_config
from .models import DomainAnalysis


class ClaudeClient:
    """Client for interacting with Claude API for AI-powered threat analysis."""

    def __init__(self):
        self.config = get_config().claude
        self.api_key = self.config.api_key
        self.enabled = self.config.enabled
        self.model = self.config.model
        self.timeout = self.config.timeout
        self.max_tokens = self.config.max_tokens

    async def analyze_threat(self, domain_analysis: DomainAnalysis) -> Optional[Dict[str, Any]]:
        """
        Generate AI-powered threat analysis using Claude.
        
        Args:
            domain_analysis: The domain analysis results to analyze
            
        Returns:
            Dictionary containing Claude's analysis, or None if not available
        """
        if not self.enabled or not self.api_key:
            return None

        try:
            # Prepare domain data for Claude
            domain_data = self._prepare_domain_data(domain_analysis)
            
            # Create the prompt
            prompt = f"""Analyze the following domain threat intelligence data from a cybersecurity threat researcher's perspective:

{domain_data}

Please provide:

1. Summary (2-3 sentences)
2. Threat type and confidence level
3. Risk level (Critical/High/Medium/Low) with key reasons
4. Recommended next steps (3-5 actions)

Be concise and actionable.
"""

            # Call Claude API
            analysis = await self._call_claude_api(prompt)
            
            # Parse Claude's response to extract risk scoring and recommendations
            if analysis and "analysis" in analysis:
                parsed_analysis = self._parse_claude_response(analysis["analysis"])
                analysis.update(parsed_analysis)
            
            return analysis
            
        except Exception as e:
            print(f"Warning: Claude API error: {e}")
            return None

    def _prepare_domain_data(self, domain_analysis: DomainAnalysis) -> str:
        """Prepare domain analysis data for Claude in a structured format."""
        data = {
            "domain": domain_analysis.domain,
            "risk_assessment": {
                "overall_score": domain_analysis.risk_score.overall_score,
                "threat_level": domain_analysis.risk_score.threat_level.value,
                "confidence": domain_analysis.risk_score.confidence,
                "breakdown": {
                    "registration_age_score": domain_analysis.risk_score.registration_age_score,
                    "country_risk_score": domain_analysis.risk_score.country_risk_score,
                    "randomness_score": domain_analysis.risk_score.randomness_score,
                    "otx_score": domain_analysis.risk_score.otx_score,
                    "virustotal_score": domain_analysis.risk_score.virustotal_score
                }
            },
            "domain_info": {
                "registration_date": domain_analysis.registration_date.isoformat() if domain_analysis.registration_date else None,
                "days_since_registration": domain_analysis.days_since_registration,
                "country": domain_analysis.country,
                "registrar": domain_analysis.registrar,
                "is_randomized": domain_analysis.is_randomized
            },
            "threat_intelligence": {
                "otx": domain_analysis.otx_data,
                "virustotal": domain_analysis.virustotal_data
            },
            "remediation_steps": domain_analysis.remediation_steps
        }
        
        return json.dumps(data, indent=2)

    async def _call_claude_api(self, prompt: str) -> Dict[str, Any]:
        """Call Claude API with the given prompt."""
        import aiohttp
        
        headers = {
            "x-api-key": self.api_key,
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01"
        }
        
        payload = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        }
        
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
            async with session.post(
                "https://api.anthropic.com/v1/messages",
                headers=headers,
                json=payload
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    return {
                        "analysis": result["content"][0]["text"],
                        "model": self.model,
                        "timestamp": datetime.now().isoformat()
                    }
                else:
                    error_text = await response.text()
                    raise Exception(f"Claude API error: {response.status} - {error_text}")

    async def test_connection(self) -> bool:
        """Test connection to Claude API."""
        if not self.enabled or not self.api_key:
            return False
        
        try:
            # Test with a simple prompt
            test_prompt = "Analyze this simple test: domain=example.com, risk_score=1.0/10"
            result = await self._call_claude_api(test_prompt)
            return result is not None
        except Exception:
            return False
    
    def _parse_claude_response(self, claude_text: str) -> Dict[str, Any]:
        """Parse Claude's response to extract structured data."""
        import re
        
        parsed = {
            "risk_score": 5.0,  # Default medium risk
            "threat_level": "medium",
            "recommendations": []
        }
        
        try:
            # Extract risk level from the response
            risk_patterns = [
                r"risk level[:\s]+(critical|high|medium|low)",
                r"overall risk[:\s]+(critical|high|medium|low)",
                r"threat level[:\s]+(critical|high|medium|low)"
            ]
            
            for pattern in risk_patterns:
                match = re.search(pattern, claude_text, re.IGNORECASE)
                if match:
                    risk_level = match.group(1).lower()
                    parsed["threat_level"] = risk_level
                    
                    # Convert to numeric score
                    risk_scores = {
                        "critical": 9.0,
                        "high": 7.0,
                        "medium": 5.0,
                        "low": 2.0
                    }
                    parsed["risk_score"] = risk_scores.get(risk_level, 5.0)
                    break
            
            # Extract recommendations
            recommendations = []
            lines = claude_text.split('\n')
            in_recommendations = False
            
            for line in lines:
                line = line.strip()
                if "recommended actions" in line.lower() or "immediate steps" in line.lower():
                    in_recommendations = True
                    continue
                elif in_recommendations and line and not line.startswith('#'):
                    # Clean up the line
                    clean_line = re.sub(r'^[-*•]\s*', '', line)
                    clean_line = re.sub(r'^\d+\.\s*', '', clean_line)
                    if clean_line and len(clean_line) > 10:  # Filter out short lines
                        recommendations.append(clean_line)
                elif in_recommendations and line.startswith('#'):
                    break
            
            parsed["recommendations"] = recommendations[:10]  # Limit to 10 recommendations
            
        except Exception as e:
            print(f"Warning: Error parsing Claude response: {e}")
        
        return parsed
