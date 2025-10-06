"""Configuration management for ThreatLookup."""

import os
import json
from pathlib import Path
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field


class OTXConfig(BaseModel):
    """OTX API configuration."""
    api_key: Optional[str] = None
    base_url: str = "https://otx.alienvault.com/api/v1"
    timeout: int = 30
    enabled: bool = True


class ThreatLookupConfig(BaseModel):
    """Main configuration for ThreatLookup."""
    otx: OTXConfig = Field(default_factory=OTXConfig)
    cache_duration: int = 3600  # 1 hour in seconds
    max_retries: int = 3
    user_agent: str = "ThreatLookup/0.1.0"


class ConfigManager:
    """Manages configuration loading and saving."""
    
    def __init__(self, config_dir: Optional[Path] = None):
        """Initialize configuration manager."""
        if config_dir is None:
            # Use XDG config directory or fallback to ~/.threatlookup
            config_dir = Path.home() / ".threatlookup"
        
        self.config_dir = config_dir
        self.config_file = config_dir / "config.json"
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        self._config: Optional[ThreatLookupConfig] = None
    
    def load_config(self) -> ThreatLookupConfig:
        """Load configuration from file and environment variables."""
        if self._config is not None:
            return self._config
        
        # Start with default config
        config_data = {}
        
        # Load from file if it exists
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    file_config = json.load(f)
                    config_data.update(file_config)
            except (json.JSONDecodeError, IOError) as e:
                print(f"Warning: Could not load config file: {e}")
        
        # Override with environment variables
        env_config = self._load_from_environment()
        config_data.update(env_config)
        
        # Create config object
        self._config = ThreatLookupConfig(**config_data)
        return self._config
    
    def save_config(self, config: ThreatLookupConfig) -> None:
        """Save configuration to file."""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config.dict(), f, indent=2)
        except IOError as e:
            print(f"Warning: Could not save config file: {e}")
    
    def _load_from_environment(self) -> Dict[str, Any]:
        """Load configuration from environment variables."""
        env_config = {}
        
        # OTX configuration
        if os.getenv('THREATLOOKUP_OTX_API_KEY'):
            env_config['otx'] = {
                'api_key': os.getenv('THREATLOOKUP_OTX_API_KEY'),
                'enabled': True
            }
        
        if os.getenv('THREATLOOKUP_OTX_BASE_URL'):
            if 'otx' not in env_config:
                env_config['otx'] = {}
            env_config['otx']['base_url'] = os.getenv('THREATLOOKUP_OTX_BASE_URL')
        
        if os.getenv('THREATLOOKUP_OTX_TIMEOUT'):
            if 'otx' not in env_config:
                env_config['otx'] = {}
            env_config['otx']['timeout'] = int(os.getenv('THREATLOOKUP_OTX_TIMEOUT'))
        
        if os.getenv('THREATLOOKUP_OTX_ENABLED'):
            if 'otx' not in env_config:
                env_config['otx'] = {}
            env_config['otx']['enabled'] = os.getenv('THREATLOOKUP_OTX_ENABLED').lower() in ('true', '1', 'yes')
        
        return env_config
    
    def setup_interactive(self) -> ThreatLookupConfig:
        """Interactive setup for first-time configuration."""
        print("🔧 ThreatLookup Configuration Setup")
        print("=" * 40)
        
        config = self.load_config()
        
        # OTX setup
        print("\n📡 OpenThreatExchange (OTX) Configuration")
        print("Get your free API key at: https://otx.alienvault.com/")
        
        if not config.otx.api_key:
            api_key = input("Enter your OTX API key (or press Enter to skip): ").strip()
            if api_key:
                config.otx.api_key = api_key
                config.otx.enabled = True
                print("✅ OTX integration enabled")
            else:
                config.otx.enabled = False
                print("⚠️  OTX integration disabled")
        else:
            print(f"✅ OTX API key already configured")
            enable = input("Enable OTX integration? (y/N): ").strip().lower()
            if enable in ('y', 'yes'):
                config.otx.enabled = True
            else:
                config.otx.enabled = False
        
        # Save configuration
        self.save_config(config)
        print(f"\n💾 Configuration saved to: {self.config_file}")
        
        return config


def get_config() -> ThreatLookupConfig:
    """Get the current configuration."""
    manager = ConfigManager()
    return manager.load_config()
