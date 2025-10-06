"""Domain analysis module for threat assessment."""

import re
import whois
from datetime import datetime, timedelta
from typing import Optional

from .models import DomainAnalysis, RiskScore, ThreatLevel, WhoisData
from .otx_client import OTXClient, OTXThreatData
from .virustotal_client import VirusTotalClient, VirusTotalDomainData
from .claude_client import ClaudeClient


class DomainAnalyzer:
    """Analyzes domains for threat indicators using WHOIS data and heuristics."""
    
    # Suspicious countries based on threat intelligence
    SUSPICIOUS_COUNTRIES = {"CN", "RU", "IR", "KP", "BY"}
    
    # Patterns that indicate randomized domain names
    RANDOM_PATTERNS = [
        r'^[a-z0-9]{8,}$',  # Long alphanumeric strings
        r'^[a-z]{3,}\d{3,}[a-z]{3,}$',  # Mixed letters and numbers
        r'^[a-z]+\d+[a-z]+\d+$',  # Alternating pattern
        r'^[a-z]{2,}\d{2,}[a-z]{2,}\d{2,}$',  # Complex alternating
    ]
    
    def __init__(self):
        """Initialize the domain analyzer."""
        self._compiled_patterns = [re.compile(pattern, re.IGNORECASE) 
                                 for pattern in self.RANDOM_PATTERNS]
        self.otx_client = OTXClient()
        self.virustotal_client = VirusTotalClient()
        self.claude_client = ClaudeClient()
    
    async def analyze_domain(self, domain: str) -> DomainAnalysis:
        """
        Analyze a domain for threat indicators.
        
        Args:
            domain: The domain name to analyze
            
        Returns:
            DomainAnalysis object with threat assessment
        """
        # Clean and validate domain
        clean_domain = self._clean_domain(domain)
        if not self._is_valid_domain(clean_domain):
            raise ValueError(f"Invalid domain format: {domain}")
        
        # Get WHOIS data
        whois_data = await self._get_whois_data(clean_domain)
        
        # Get OTX threat intelligence data
        otx_data = await self.otx_client.get_domain_info(clean_domain)
        
        # Get VirusTotal threat intelligence data
        virustotal_data = await self.virustotal_client.get_domain_info(clean_domain)
        
        # Calculate basic risk factors for data collection
        registration_age_score = self._calculate_registration_age_score(whois_data)
        country_risk_score = self._calculate_country_risk_score(whois_data)
        randomness_score = self._calculate_randomness_score(clean_domain)
        otx_score = self._calculate_otx_score(otx_data)
        virustotal_score = self._calculate_virustotal_score(virustotal_data)
        
        # Calculate days since registration
        days_since_registration = None
        if whois_data.registration_date:
            days_since_registration = (datetime.now() - whois_data.registration_date).days
        
        # Prepare OTX data for output
        otx_output = None
        if otx_data:
            otx_output = {
                "is_malicious": otx_data.is_malicious,
                "threat_score": otx_data.threat_score,
                "pulse_count": otx_data.pulse_count,
                "malware_families": otx_data.malware_families,
                "attack_types": otx_data.attack_types,
                "confidence": otx_data.confidence
            }
        
        # Prepare VirusTotal data for output
        virustotal_output = None
        if virustotal_data:
            virustotal_output = {
                "is_malicious": virustotal_data.is_malicious,
                "threat_score": virustotal_data.threat_score,
                "detection_engines": virustotal_data.detection_engines,
                "malicious_engines": virustotal_data.malicious_engines,
                "categories": virustotal_data.categories,
                "reputation": virustotal_data.reputation,
                "last_analysis_date": virustotal_data.last_analysis_date.isoformat() if virustotal_data.last_analysis_date else None,
                "confidence": virustotal_data.confidence
            }
        
        # Get Claude AI analysis with complete data
        claude_analysis = await self.claude_client.analyze_threat(
            DomainAnalysis(
                domain=clean_domain,
                registration_date=whois_data.registration_date,
                country=whois_data.country,
                registrar=whois_data.registrar,
                days_since_registration=days_since_registration,
                is_randomized=self._is_randomized_domain(clean_domain),
                risk_score=RiskScore(
                    overall_score=0,  # Will be set by Claude
                    threat_level=ThreatLevel.LOW,
                    registration_age_score=registration_age_score,
                    country_risk_score=country_risk_score,
                    randomness_score=randomness_score,
                    otx_score=otx_score,
                    virustotal_score=virustotal_score,
                    confidence=0
                ),
                remediation_steps=[],
                otx_data=otx_output,
                virustotal_data=virustotal_output,
                claude_analysis=None
            )
        )
        
        # Use Claude's risk scoring and recommendations if available
        if claude_analysis:
            claude_risk_score = claude_analysis.get("risk_score", 5.0)
            claude_threat_level = claude_analysis.get("threat_level", "medium")
            claude_recommendations = claude_analysis.get("recommendations", [])
            
            # Convert Claude's threat level to our enum
            threat_level_map = {
                "critical": ThreatLevel.CRITICAL,
                "high": ThreatLevel.HIGH,
                "medium": ThreatLevel.MEDIUM,
                "low": ThreatLevel.LOW
            }
            threat_level = threat_level_map.get(claude_threat_level, ThreatLevel.MEDIUM)
            
            # Use Claude's recommendations
            remediation_steps = claude_recommendations
        else:
            # Fallback to our original logic if Claude is not available
            claude_risk_score = self._calculate_overall_risk_score(
                registration_age_score, country_risk_score, randomness_score, otx_score, virustotal_score
            )
            threat_level = self._determine_threat_level(claude_risk_score)
            remediation_steps = self._generate_remediation_steps(
                threat_level, whois_data, clean_domain, otx_data, virustotal_data
            )
        
        # Create risk score object using Claude's analysis
        risk_score = RiskScore(
            overall_score=claude_risk_score,
            threat_level=threat_level,
            registration_age_score=registration_age_score,
            country_risk_score=country_risk_score,
            randomness_score=randomness_score,
            otx_score=otx_score,
            virustotal_score=virustotal_score,
            confidence=self._calculate_confidence(whois_data, otx_data, virustotal_data)
        )
        
        return DomainAnalysis(
            domain=clean_domain,
            registration_date=whois_data.registration_date,
            country=whois_data.country,
            registrar=whois_data.registrar,
            days_since_registration=days_since_registration,
            is_randomized=self._is_randomized_domain(clean_domain),
            risk_score=risk_score,
            remediation_steps=remediation_steps,
            otx_data=otx_output,
            virustotal_data=virustotal_output,
            claude_analysis=claude_analysis
        )
    
    def _clean_domain(self, domain: str) -> str:
        """Clean and normalize domain name."""
        domain = domain.strip().lower()
        # Remove protocol if present
        if domain.startswith(('http://', 'https://')):
            domain = domain.split('://', 1)[1]
        # Remove www prefix
        if domain.startswith('www.'):
            domain = domain[4:]
        # Remove trailing slash
        domain = domain.rstrip('/')
        return domain
    
    def _is_valid_domain(self, domain: str) -> bool:
        """Validate domain format."""
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(domain_pattern, domain))
    
    async def _get_whois_data(self, domain: str) -> WhoisData:
        """Get WHOIS data for the domain."""
        try:
            whois_info = whois.whois(domain)
            
            # Extract registration date
            registration_date = None
            if hasattr(whois_info, 'creation_date'):
                if isinstance(whois_info.creation_date, list):
                    registration_date = whois_info.creation_date[0]
                else:
                    registration_date = whois_info.creation_date
            
            # Extract country
            country = None
            if hasattr(whois_info, 'country'):
                if isinstance(whois_info.country, list):
                    country = whois_info.country[0]
                else:
                    country = whois_info.country
            
            # Extract registrar
            registrar = None
            if hasattr(whois_info, 'registrar'):
                if isinstance(whois_info.registrar, list):
                    registrar = whois_info.registrar[0]
                else:
                    registrar = whois_info.registrar
            
            # Extract name servers
            name_servers = []
            if hasattr(whois_info, 'name_servers'):
                if isinstance(whois_info.name_servers, list):
                    name_servers = whois_info.name_servers
                else:
                    name_servers = [whois_info.name_servers]
            
            # Extract status
            status = []
            if hasattr(whois_info, 'status'):
                if isinstance(whois_info.status, list):
                    status = whois_info.status
                else:
                    status = [whois_info.status]
            
            return WhoisData(
                domain=domain,
                registration_date=registration_date,
                country=country,
                registrar=registrar,
                name_servers=name_servers,
                status=status
            )
            
        except Exception as e:
            # Return minimal data if WHOIS lookup fails
            return WhoisData(domain=domain)
    
    def _calculate_registration_age_score(self, whois_data: WhoisData) -> float:
        """Calculate risk score based on registration age."""
        if not whois_data.registration_date:
            return 5.0  # Medium risk if no registration date available
        
        days_old = (datetime.now() - whois_data.registration_date).days
        
        if days_old < 7:
            return 10.0  # Very highly suspicious
        elif days_old < 14:
            return 8.5   # Highly suspicious
        elif days_old < 30:
            return 7.0   # Suspicious
        elif days_old < 90:
            return 4.0   # Somewhat suspicious
        elif days_old < 365:
            return 2.0   # Low risk
        else:
            return 1.0   # Very low risk
    
    def _calculate_country_risk_score(self, whois_data: WhoisData) -> float:
        """Calculate risk score based on registration country."""
        if not whois_data.country:
            return 3.0  # Medium risk if country unknown
        
        country_code = whois_data.country.upper()
        
        if country_code in self.SUSPICIOUS_COUNTRIES:
            return 8.0  # High risk for suspicious countries
        else:
            return 1.0  # Low risk for other countries
    
    def _calculate_randomness_score(self, domain: str) -> float:
        """Calculate risk score based on domain name randomness."""
        if self._is_randomized_domain(domain):
            return 7.0  # High risk for randomized domains
        else:
            return 1.0  # Low risk for normal domains
    
    def _is_randomized_domain(self, domain: str) -> bool:
        """Check if domain name appears randomized."""
        # Remove TLD for analysis
        domain_name = domain.split('.')[0]
        
        # Check against patterns
        for pattern in self._compiled_patterns:
            if pattern.match(domain_name):
                return True
        
        # Check for excessive character repetition
        if len(set(domain_name)) < len(domain_name) * 0.3:
            return True
        
        # Check for excessive numbers
        digit_ratio = sum(c.isdigit() for c in domain_name) / len(domain_name)
        if digit_ratio > 0.5:
            return True
        
        return False
    
    def _calculate_otx_score(self, otx_data: Optional[OTXThreatData]) -> float:
        """Calculate risk score based on OTX threat intelligence."""
        if not otx_data:
            return 3.0  # Medium risk if no OTX data available
        
        if not otx_data.is_malicious:
            return 1.0  # Low risk if not found in OTX
        
        # Enhanced scoring based on OTX data
        base_score = otx_data.threat_score
        
        # Boost score for high pulse count
        if otx_data.pulse_count > 5:
            base_score += 2.0
        elif otx_data.pulse_count > 2:
            base_score += 1.0
        
        # Boost score for malware families
        if len(otx_data.malware_families) > 0:
            base_score += 1.5
        
        # Boost score for multiple attack types
        if len(otx_data.attack_types) > 1:
            base_score += 1.0
        
        return min(base_score, 10.0)
    
    def _calculate_virustotal_score(self, virustotal_data: Optional[VirusTotalDomainData]) -> float:
        """Calculate risk score based on VirusTotal threat intelligence."""
        if not virustotal_data:
            return 0.0  # No score if no VirusTotal data available
        
        if not virustotal_data.is_malicious:
            return 1.0  # Low risk if not detected by VirusTotal
        
        # Use VirusTotal threat score directly
        base_score = virustotal_data.threat_score
        
        # Boost score for high malicious engine count
        if virustotal_data.malicious_engines > 5:
            base_score += 2.0
        elif virustotal_data.malicious_engines > 2:
            base_score += 1.0
        
        # Boost score for negative reputation
        if virustotal_data.reputation < 0:
            base_score += 1.5
        
        return min(base_score, 10.0)
    
    def _calculate_overall_risk_score(self, age_score: float, country_score: float, 
                                    randomness_score: float, otx_score: float, 
                                    virustotal_score: float) -> float:
        """Calculate weighted overall risk score."""
        # Weighted average with threat intelligence being most important
        if otx_score > 0 or virustotal_score > 0:
            # Both threat intelligence sources available
            if otx_score > 0 and virustotal_score > 0:
                # Both OTX and VirusTotal available - balanced approach
                weights = {'otx': 0.2, 'virustotal': 0.2, 'age': 0.2, 'country': 0.2, 'randomness': 0.2}
            elif otx_score > 0:
                # Only OTX available
                weights = {'otx': 0.4, 'age': 0.25, 'country': 0.2, 'randomness': 0.15}
            else:  # virustotal_score > 0
                # Only VirusTotal available
                weights = {'virustotal': 0.4, 'age': 0.25, 'country': 0.2, 'randomness': 0.15}
            
            weighted_score = (
                otx_score * weights.get('otx', 0) +
                virustotal_score * weights.get('virustotal', 0) +
                age_score * weights['age'] +
                country_score * weights['country'] +
                randomness_score * weights['randomness']
            )
        else:
            # Fallback to original weights if no threat intelligence data
            weights = {'age': 0.5, 'country': 0.3, 'randomness': 0.2}
            weighted_score = (
                age_score * weights['age'] +
                country_score * weights['country'] +
                randomness_score * weights['randomness']
            )
        
        return min(weighted_score, 10.0)  # Cap at 10.0
    
    def _determine_threat_level(self, score: float) -> ThreatLevel:
        """Determine threat level based on risk score."""
        if score >= 8.0:
            return ThreatLevel.CRITICAL
        elif score >= 6.0:
            return ThreatLevel.HIGH
        elif score >= 4.0:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW
    
    def _calculate_confidence(self, whois_data: WhoisData, otx_data: Optional[OTXThreatData], 
                            virustotal_data: Optional[VirusTotalDomainData]) -> float:
        """Calculate confidence in the assessment."""
        confidence = 0.5  # Base confidence
        
        if whois_data.registration_date:
            confidence += 0.15
        if whois_data.country:
            confidence += 0.1
        
        # Boost confidence with threat intelligence data
        if otx_data:
            confidence += 0.2
            if otx_data.confidence > 0.8:
                confidence += 0.05
        
        if virustotal_data:
            confidence += 0.2
            if virustotal_data.confidence > 0.8:
                confidence += 0.05
        
        return min(confidence, 1.0)
    
    def _generate_remediation_steps(self, threat_level: ThreatLevel, 
                                  whois_data: WhoisData, domain: str, 
                                  otx_data: Optional[OTXThreatData],
                                  virustotal_data: Optional[VirusTotalDomainData]) -> list[str]:
        """Generate remediation steps based on threat level and findings."""
        steps = []
        
        if threat_level == ThreatLevel.CRITICAL:
            steps.extend([
                "IMMEDIATE ACTION REQUIRED: Block this domain at all network boundaries",
                "Add to blacklist in DNS filtering systems",
                "Alert security team for immediate investigation",
                "Check for any existing connections to this domain",
                "Review logs for suspicious activity related to this domain"
            ])
        elif threat_level == ThreatLevel.HIGH:
            steps.extend([
                "Add to high-priority monitoring list",
                "Block in corporate DNS filtering",
                "Investigate any recent connections to this domain",
                "Consider blocking at firewall level",
                "Monitor for any phishing or malware campaigns"
            ])
        elif threat_level == ThreatLevel.MEDIUM:
            steps.extend([
                "Add to watch list for monitoring",
                "Review security policies for similar domains",
                "Consider implementing additional filtering rules",
                "Monitor for any suspicious activity"
            ])
        else:
            steps.extend([
                "Continue normal monitoring",
                "Review periodically for any changes in threat landscape"
            ])
        
        # Add specific recommendations based on findings
        if whois_data.country and whois_data.country.upper() in self.SUSPICIOUS_COUNTRIES:
            steps.append(f"Exercise extra caution - domain registered in {whois_data.country}")
        
        if self._is_randomized_domain(domain):
            steps.append("Domain appears randomized - typical of malicious domains")
        
        # Add OTX-specific recommendations
        if otx_data and otx_data.is_malicious:
            steps.append(f"🚨 THREAT INTELLIGENCE ALERT: Domain found in {otx_data.pulse_count} threat pulses")
            
            if otx_data.malware_families:
                families = ", ".join(otx_data.malware_families[:3])
                steps.append(f"Associated with malware families: {families}")
            
            if otx_data.attack_types:
                attacks = ", ".join(otx_data.attack_types[:3])
                steps.append(f"Linked to attack types: {attacks}")
            
            if otx_data.references:
                steps.append(f"Review {len(otx_data.references)} threat intelligence references")
                steps.append("Check OTX pulse details for additional context")
        
        elif otx_data and not otx_data.is_malicious:
            steps.append("✅ No threat intelligence found - domain not in known threat databases")
        
        # Add VirusTotal-specific recommendations
        if virustotal_data and virustotal_data.is_malicious:
            steps.append(f"🛡️  VIRUSTOTAL ALERT: Domain detected by {virustotal_data.malicious_engines} security engines")
            
            if virustotal_data.categories:
                categories = ", ".join(virustotal_data.categories[:3])
                steps.append(f"Domain categories: {categories}")
            
            if virustotal_data.reputation < 0:
                steps.append(f"Negative reputation score: {virustotal_data.reputation}")
            
            if virustotal_data.last_analysis_date:
                steps.append(f"Last analyzed: {virustotal_data.last_analysis_date.strftime('%Y-%m-%d')}")
        
        elif virustotal_data and not virustotal_data.is_malicious:
            steps.append("✅ VirusTotal: No malicious detections found")
            if virustotal_data.detection_engines > 0:
                steps.append(f"Analyzed by {virustotal_data.detection_engines} security engines")
        
        return steps
