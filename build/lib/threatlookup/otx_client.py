"""OpenThreatExchange (OTX) API client for threat intelligence."""

import asyncio
import aiohttp
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from dataclasses import dataclass

from .config import get_config


@dataclass
class OTXThreatData:
    """OTX threat intelligence data."""
    domain: str
    is_malicious: bool
    threat_score: float
    pulse_count: int
    malware_families: List[str]
    attack_types: List[str]
    references: List[str]
    last_updated: Optional[datetime] = None
    confidence: float = 0.0


class OTXClient:
    """Client for OpenThreatExchange API."""
    
    def __init__(self, api_key: Optional[str] = None, base_url: Optional[str] = None):
        """Initialize OTX client."""
        config = get_config()
        
        self.api_key = api_key or config.otx.api_key
        self.base_url = base_url or config.otx.base_url
        self.timeout = config.otx.timeout
        self.enabled = config.otx.enabled and bool(self.api_key)
        
        if not self.enabled:
            return
        
        self.headers = {
            'X-OTX-API-KEY': self.api_key,
            'User-Agent': config.user_agent,
            'Content-Type': 'application/json'
        }
    
    async def get_domain_info(self, domain: str) -> Optional[OTXThreatData]:
        """
        Get threat intelligence data for a domain.
        
        Args:
            domain: The domain to analyze
            
        Returns:
            OTXThreatData object with threat intelligence, or None if not available
        """
        if not self.enabled:
            return None
        
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                url = f"{self.base_url}/indicators/domain/{domain}/general"
                
                async with session.get(url, headers=self.headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_domain_data(domain, data)
                    elif response.status == 404:
                        # Domain not found in OTX - not necessarily malicious
                        return OTXThreatData(
                            domain=domain,
                            is_malicious=False,
                            threat_score=0.0,
                            pulse_count=0,
                            malware_families=[],
                            attack_types=[],
                            references=[],
                            confidence=0.8  # High confidence in "not found" result
                        )
                    else:
                        print(f"Warning: OTX API returned status {response.status}")
                        return None
                        
        except asyncio.TimeoutError:
            print("Warning: OTX API request timed out")
            return None
        except Exception as e:
            print(f"Warning: OTX API error: {e}")
            return None
    
    def _parse_domain_data(self, domain: str, data: Dict[str, Any]) -> OTXThreatData:
        """Parse OTX API response data."""
        # Extract pulse information
        pulses = data.get('pulse_info', {}).get('pulses', [])
        pulse_count = len(pulses)
        
        # Determine if malicious based on pulse count and content
        is_malicious = pulse_count > 0
        
        # Calculate threat score based on pulse data
        threat_score = self._calculate_threat_score(pulses)
        
        # Extract malware families and attack types
        malware_families = []
        attack_types = []
        references = []
        
        for pulse in pulses:
            # Extract malware families
            tags = pulse.get('tags', [])
            for tag in tags:
                if tag.lower() in ['malware', 'trojan', 'virus', 'backdoor', 'rootkit']:
                    malware_families.append(tag)
            
            # Extract attack types
            name = pulse.get('name', '').lower()
            if any(term in name for term in ['phishing', 'malware', 'trojan', 'backdoor']):
                attack_types.append(name)
            
            # Extract references
            if 'references' in pulse:
                references.extend(pulse['references'])
        
        # Remove duplicates
        malware_families = list(set(malware_families))
        attack_types = list(set(attack_types))
        references = list(set(references))
        
        # Calculate confidence based on data quality
        confidence = self._calculate_confidence(pulse_count, len(malware_families), len(attack_types))
        
        return OTXThreatData(
            domain=domain,
            is_malicious=is_malicious,
            threat_score=threat_score,
            pulse_count=pulse_count,
            malware_families=malware_families,
            attack_types=attack_types,
            references=references,
            last_updated=datetime.now(),
            confidence=confidence
        )
    
    def _calculate_threat_score(self, pulses: List[Dict[str, Any]]) -> float:
        """Calculate threat score from pulse data."""
        if not pulses:
            return 0.0
        
        # Base score from pulse count
        base_score = min(len(pulses) * 2.0, 10.0)
        
        # Adjust based on pulse quality indicators
        quality_multiplier = 1.0
        
        for pulse in pulses:
            # Higher score for more recent pulses
            if 'modified' in pulse:
                try:
                    modified_date = datetime.fromisoformat(pulse['modified'].replace('Z', '+00:00'))
                    days_old = (datetime.now() - modified_date.replace(tzinfo=None)).days
                    if days_old < 30:
                        quality_multiplier += 0.2
                except:
                    pass
            
            # Higher score for pulses with more indicators
            indicator_count = len(pulse.get('indicators', []))
            if indicator_count > 10:
                quality_multiplier += 0.3
            
            # Higher score for pulses with more references
            ref_count = len(pulse.get('references', []))
            if ref_count > 5:
                quality_multiplier += 0.2
        
        return min(base_score * quality_multiplier, 10.0)
    
    def _calculate_confidence(self, pulse_count: int, malware_family_count: int, attack_type_count: int) -> float:
        """Calculate confidence in the threat assessment."""
        if pulse_count == 0:
            return 0.8  # High confidence in "not malicious" result
        
        # Base confidence from pulse count
        confidence = min(0.5 + (pulse_count * 0.1), 0.9)
        
        # Boost confidence with additional indicators
        if malware_family_count > 0:
            confidence += 0.1
        if attack_type_count > 0:
            confidence += 0.1
        
        return min(confidence, 1.0)
    
    async def test_connection(self) -> bool:
        """Test connection to OTX API."""
        if not self.enabled:
            return False
        
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                # Test with a known domain
                url = f"{self.base_url}/indicators/domain/google.com/general"
                
                async with session.get(url, headers=self.headers) as response:
                    return response.status in [200, 404]  # 404 is OK for test
                    
        except Exception:
            return False
