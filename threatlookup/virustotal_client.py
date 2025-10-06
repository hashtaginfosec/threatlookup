"""VirusTotal API client using the official vt-py library."""

import asyncio
import time
from datetime import datetime
from typing import Optional, Dict, Any, List
from dataclasses import dataclass

import vt
from .config import get_config


@dataclass
class VirusTotalDomainData:
    """VirusTotal domain analysis data."""
    domain: str
    is_malicious: bool
    threat_score: float
    detection_engines: int
    malicious_engines: int
    last_analysis_date: Optional[datetime] = None
    categories: List[str] = None
    reputation: int = 0
    confidence: float = 0.0


class VirusTotalClient:
    """Client for VirusTotal API using the official vt-py library."""
    
    def __init__(self, api_key: Optional[str] = None, base_url: Optional[str] = None):
        """Initialize VirusTotal client."""
        config = get_config()
        
        self.api_key = api_key or config.virustotal.api_key
        self.base_url = base_url or config.virustotal.base_url
        self.timeout = config.virustotal.timeout
        self.rate_limit_delay = config.virustotal.rate_limit_delay
        self.enabled = config.virustotal.enabled and bool(self.api_key)
        
        if not self.enabled:
            return
        
        # Initialize the VirusTotal client
        self.client = vt.Client(self.api_key)
    
    async def get_domain_info(self, domain: str) -> Optional[VirusTotalDomainData]:
        """
        Get threat intelligence data for a domain.
        
        Args:
            domain: The domain to analyze
            
        Returns:
            VirusTotalDomainData object with threat intelligence, or None if not available
        """
        if not self.enabled:
            return None
        
        try:
            # Rate limiting
            await asyncio.sleep(self.rate_limit_delay)
            
            # Use synchronous approach to avoid async conflicts
            domain_info = self._get_domain_sync(domain)
            return domain_info
            
        except Exception as e:
            print(f"Warning: VirusTotal API error: {e}")
            return None
    
    async def _get_domain_async(self, domain: str) -> Optional[VirusTotalDomainData]:
        """Async domain lookup for use in new event loop."""
        try:
            # Get domain object
            domain_obj = await self.client.get_object_async(f"/domains/{domain}")
            
            # Extract last analysis stats
            last_analysis_stats = domain_obj.get("last_analysis_stats", {})
            malicious_count = last_analysis_stats.get("malicious", 0)
            suspicious_count = last_analysis_stats.get("suspicious", 0)
            undetected_count = last_analysis_stats.get("undetected", 0)
            harmless_count = last_analysis_stats.get("harmless", 0)
            
            total_engines = malicious_count + suspicious_count + undetected_count + harmless_count
            
            # Calculate threat score
            threat_score = self._calculate_threat_score(malicious_count, suspicious_count, total_engines)
            
            # Determine if malicious
            is_malicious = malicious_count > 0 or suspicious_count > 2
            
            # Extract categories
            categories = []
            if "categories" in domain_obj:
                categories = list(domain_obj["categories"].values())
            
            # Extract reputation
            reputation = domain_obj.get("reputation", 0)
            
            # Extract last analysis date
            last_analysis_date = None
            if "last_analysis_date" in domain_obj:
                timestamp = domain_obj["last_analysis_date"]
                last_analysis_date = datetime.fromtimestamp(timestamp)
            
            # Calculate confidence
            confidence = self._calculate_confidence(malicious_count, suspicious_count, total_engines)
            
            return VirusTotalDomainData(
                domain=domain,
                is_malicious=is_malicious,
                threat_score=threat_score,
                detection_engines=total_engines,
                malicious_engines=malicious_count,
                last_analysis_date=last_analysis_date,
                categories=categories,
                reputation=reputation,
                confidence=confidence
            )
            
        except vt.APIError as e:
            if e.code == "NotFoundError":
                # Domain not found in VirusTotal - not necessarily malicious
                return VirusTotalDomainData(
                    domain=domain,
                    is_malicious=False,
                    threat_score=0.0,
                    detection_engines=0,
                    malicious_engines=0,
                    confidence=0.8  # High confidence in "not found" result
                )
            else:
                print(f"Warning: VirusTotal API error: {e}")
                return None
        except Exception as e:
            print(f"Warning: VirusTotal error: {e}")
            return None
    
    def _get_domain_sync(self, domain: str) -> Optional[VirusTotalDomainData]:
        """Synchronous domain lookup using requests instead of vt-py to avoid async issues."""
        try:
            import requests
            
            # Use direct API calls to avoid async conflicts
            headers = {
                "x-apikey": self.api_key,
                "User-Agent": "ThreatLookup/0.1.0"
            }
            
            # Get domain information
            response = requests.get(
                f"{self.base_url}/domains/{domain}",
                headers=headers,
                timeout=self.timeout
            )
            
            if response.status_code == 404:
                # Domain not found in VirusTotal - not necessarily malicious
                return VirusTotalDomainData(
                    domain=domain,
                    is_malicious=False,
                    threat_score=0.0,
                    detection_engines=0,
                    malicious_engines=0,
                    confidence=0.8  # High confidence in "not found" result
                )
            
            if response.status_code != 200:
                print(f"Warning: VirusTotal API error: HTTP {response.status_code}")
                return None
            
            data = response.json()
            
            # Extract last analysis stats
            last_analysis_stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious_count = last_analysis_stats.get("malicious", 0)
            suspicious_count = last_analysis_stats.get("suspicious", 0)
            undetected_count = last_analysis_stats.get("undetected", 0)
            harmless_count = last_analysis_stats.get("harmless", 0)
            
            total_engines = malicious_count + suspicious_count + undetected_count + harmless_count
            
            # Calculate threat score
            threat_score = self._calculate_threat_score(malicious_count, suspicious_count, total_engines)
            
            # Determine if malicious
            is_malicious = malicious_count > 0 or suspicious_count > 2
            
            # Extract categories
            categories = []
            categories_data = data.get("data", {}).get("attributes", {}).get("categories", {})
            if categories_data:
                categories = list(categories_data.values())
            
            # Extract reputation
            reputation = data.get("data", {}).get("attributes", {}).get("reputation", 0)
            
            # Extract last analysis date
            last_analysis_date = None
            last_analysis_timestamp = data.get("data", {}).get("attributes", {}).get("last_analysis_date")
            if last_analysis_timestamp:
                last_analysis_date = datetime.fromtimestamp(last_analysis_timestamp)
            
            # Calculate confidence
            confidence = self._calculate_confidence(malicious_count, suspicious_count, total_engines)
            
            return VirusTotalDomainData(
                domain=domain,
                is_malicious=is_malicious,
                threat_score=threat_score,
                detection_engines=total_engines,
                malicious_engines=malicious_count,
                last_analysis_date=last_analysis_date,
                categories=categories,
                reputation=reputation,
                confidence=confidence
            )
            
        except Exception as e:
            print(f"Warning: VirusTotal error: {e}")
            return None
    
    def _calculate_threat_score(self, malicious_count: int, suspicious_count: int, total_engines: int) -> float:
        """Calculate threat score from VirusTotal data."""
        if total_engines == 0:
            return 0.0
        
        # Base score from malicious detections
        base_score = (malicious_count * 2.0) + (suspicious_count * 1.0)
        
        # Normalize to 0-10 scale
        max_possible_score = total_engines * 2.0
        normalized_score = (base_score / max_possible_score) * 10.0
        
        # Boost score for high malicious percentage
        malicious_percentage = malicious_count / total_engines
        if malicious_percentage > 0.5:
            normalized_score += 2.0
        elif malicious_percentage > 0.2:
            normalized_score += 1.0
        
        return min(normalized_score, 10.0)
    
    def _calculate_confidence(self, malicious_count: int, suspicious_count: int, total_engines: int) -> float:
        """Calculate confidence in the threat assessment."""
        if total_engines == 0:
            return 0.5  # Medium confidence for no data
        
        # Base confidence from engine count
        confidence = min(0.5 + (total_engines * 0.02), 0.9)
        
        # Boost confidence with detections
        if malicious_count > 0:
            confidence += 0.2
        if suspicious_count > 0:
            confidence += 0.1
        
        return min(confidence, 1.0)
    
    async def test_connection(self) -> bool:
        """Test connection to VirusTotal API."""
        if not self.enabled:
            return False
        
        try:
            # Test with a known domain
            result = self._test_connection_sync()
            return result
        except Exception:
            return False
    
    def _test_connection_sync(self) -> bool:
        """Synchronous connection test."""
        try:
            # Try to get information about a well-known domain
            domain_obj = self.client.get_object("/domains/google.com")
            return True
        except vt.APIError:
            # Even if domain not found, API is working
            return True
        except Exception:
            return False
    
    def close(self):
        """Close the VirusTotal client."""
        if hasattr(self, 'client'):
            self.client.close()
