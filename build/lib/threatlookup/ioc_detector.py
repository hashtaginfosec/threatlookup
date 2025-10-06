"""IOC (Indicator of Compromise) type detection module."""

import re
from enum import Enum
from typing import Union


class IOCType(str, Enum):
    """IOC type enumeration."""
    DOMAIN = "domain"
    IP_ADDRESS = "ip_address"
    EMAIL = "email"
    FILE_PATH = "file_path"
    FILE_HASH = "file_hash"
    UNKNOWN = "unknown"


class IOCDetector:
    """Detects the type of IOC from input string."""
    
    # IP address patterns (IPv4 and IPv6)
    IPV4_PATTERN = re.compile(
        r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    )
    
    IPV6_PATTERN = re.compile(
        r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$'
    )
    
    # Email pattern
    EMAIL_PATTERN = re.compile(
        r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    )
    
    # Domain pattern
    DOMAIN_PATTERN = re.compile(
        r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    )
    
    # File hash patterns
    MD5_PATTERN = re.compile(r'^[a-fA-F0-9]{32}$')
    SHA1_PATTERN = re.compile(r'^[a-fA-F0-9]{40}$')
    SHA256_PATTERN = re.compile(r'^[a-fA-F0-9]{64}$')
    SHA512_PATTERN = re.compile(r'^[a-fA-F0-9]{128}$')
    
    # File path patterns (basic detection)
    FILE_PATH_PATTERNS = [
        re.compile(r'^[a-zA-Z]:\\', re.IGNORECASE),  # Windows absolute path
        re.compile(r'^\\\\', re.IGNORECASE),        # Windows UNC path
        re.compile(r'^/', re.IGNORECASE),           # Unix absolute path
        re.compile(r'^\./', re.IGNORECASE),         # Unix relative path
        re.compile(r'^\.\./', re.IGNORECASE),       # Unix relative path
    ]
    
    def detect_ioc_type(self, input_string: str) -> IOCType:
        """
        Detect the type of IOC from input string.
        
        Args:
            input_string: The input string to analyze
            
        Returns:
            IOCType enum indicating the detected type
        """
        if not input_string or not isinstance(input_string, str):
            return IOCType.UNKNOWN
        
        # Clean the input
        cleaned_input = input_string.strip()
        
        # Check for file hashes first (most specific)
        if self._is_file_hash(cleaned_input):
            return IOCType.FILE_HASH
        
        # Check for IP addresses
        if self._is_ip_address(cleaned_input):
            return IOCType.IP_ADDRESS
        
        # Check for email addresses
        if self._is_email(cleaned_input):
            return IOCType.EMAIL
        
        # Check for file paths
        if self._is_file_path(cleaned_input):
            return IOCType.FILE_PATH
        
        # Check for domains (least specific, so check last)
        if self._is_domain(cleaned_input):
            return IOCType.DOMAIN
        
        return IOCType.UNKNOWN
    
    def _is_file_hash(self, input_string: str) -> bool:
        """Check if input is a file hash."""
        # Check common hash lengths
        if (self.MD5_PATTERN.match(input_string) or
            self.SHA1_PATTERN.match(input_string) or
            self.SHA256_PATTERN.match(input_string) or
            self.SHA512_PATTERN.match(input_string)):
            return True
        
        # Check for other common hash lengths
        if len(input_string) in [32, 40, 64, 128] and all(c in '0123456789abcdefABCDEF' for c in input_string):
            return True
        
        return False
    
    def _is_ip_address(self, input_string: str) -> bool:
        """Check if input is an IP address."""
        return (self.IPV4_PATTERN.match(input_string) or 
                self.IPV6_PATTERN.match(input_string))
    
    def _is_email(self, input_string: str) -> bool:
        """Check if input is an email address."""
        return bool(self.EMAIL_PATTERN.match(input_string))
    
    def _is_file_path(self, input_string: str) -> bool:
        """Check if input is a file path."""
        # Check for common file path patterns
        for pattern in self.FILE_PATH_PATTERNS:
            if pattern.match(input_string):
                return True
        
        # Check for file extensions
        if '.' in input_string and any(input_string.lower().endswith(ext) for ext in 
            ['.exe', '.dll', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', 
             '.zip', '.rar', '.7z', '.tar', '.gz', '.jpg', '.png', '.gif', '.mp4', '.avi']):
            return True
        
        return False
    
    def _is_domain(self, input_string: str) -> bool:
        """Check if input is a domain name."""
        # Remove protocol if present
        domain = input_string
        if domain.startswith(('http://', 'https://')):
            domain = domain.split('://', 1)[1]
        
        # Remove www prefix
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # Remove trailing slash
        domain = domain.rstrip('/')
        
        # Check domain pattern
        return bool(self.DOMAIN_PATTERN.match(domain))
    
    def get_clean_input(self, input_string: str, ioc_type: IOCType) -> str:
        """
        Clean the input string based on IOC type.
        
        Args:
            input_string: The input string to clean
            ioc_type: The detected IOC type
            
        Returns:
            Cleaned input string
        """
        if ioc_type == IOCType.DOMAIN:
            return self._clean_domain(input_string)
        elif ioc_type == IOCType.EMAIL:
            return input_string.strip().lower()
        elif ioc_type == IOCType.IP_ADDRESS:
            return input_string.strip()
        elif ioc_type == IOCType.FILE_HASH:
            return input_string.strip().lower()
        elif ioc_type == IOCType.FILE_PATH:
            return input_string.strip()
        else:
            return input_string.strip()
    
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
