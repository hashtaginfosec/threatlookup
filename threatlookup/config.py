import json
import os
from pathlib import Path
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field


class OTXConfig(BaseModel):
    """OpenThreatExchange API configuration."""
    api_key: Optional[str] = None
    base_url: str = "https://otx.alienvault.com/api/v1"
    timeout: int = 30
    enabled: bool = True


class VirusTotalConfig(BaseModel):
    """VirusTotal API configuration."""
    api_key: Optional[str] = None
    base_url: str = "https://www.virustotal.com/api/v3"
    timeout: int = 30
    enabled: bool = True
    rate_limit_delay: float = 0.2  # Delay between requests to respect rate limits

class ClaudeConfig(BaseModel):
    """Claude API configuration for AI-powered threat analysis."""
    api_key: Optional[str] = None
    model: str = "claude-3-5-sonnet-20241022"
    timeout: int = 60
    enabled: bool = True
    max_tokens: int = 4000


class ThreatLookupConfig(BaseModel):
    """Main configuration for ThreatLookup."""
    otx: OTXConfig = Field(default_factory=OTXConfig)
    virustotal: VirusTotalConfig = Field(default_factory=VirusTotalConfig)
    claude: ClaudeConfig = Field(default_factory=ClaudeConfig)
    cache_duration: int = 3600  # 1 hour in seconds
    max_retries: int = 3
    user_agent: str = "ThreatLookup/0.1.0"


class ConfigManager:
    """Manages configuration loading and saving."""
    
    def __init__(self):
        self.config_file = Path.home() / '.threatlookup' / 'config.json'
        self.config_file.parent.mkdir(exist_ok=True)
        self._config: Optional[ThreatLookupConfig] = None
    
    def load_config(self) -> ThreatLookupConfig:
        """Load configuration from file and environment."""
        if self._config is not None:
            return self._config
        
        # Load from file if it exists
        config_data = {}
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    config_data = json.load(f)
            except (IOError, json.JSONDecodeError) as e:
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
        
        # VirusTotal configuration
        if os.getenv('THREATLOOKUP_VIRUSTOTAL_API_KEY'):
            env_config['virustotal'] = {
                'api_key': os.getenv('THREATLOOKUP_VIRUSTOTAL_API_KEY'),
                'enabled': True
            }
        
        if os.getenv('THREATLOOKUP_VIRUSTOTAL_BASE_URL'):
            if 'virustotal' not in env_config:
                env_config['virustotal'] = {}
            env_config['virustotal']['base_url'] = os.getenv('THREATLOOKUP_VIRUSTOTAL_BASE_URL')
        
        if os.getenv('THREATLOOKUP_VIRUSTOTAL_TIMEOUT'):
            if 'virustotal' not in env_config:
                env_config['virustotal'] = {}
            env_config['virustotal']['timeout'] = int(os.getenv('THREATLOOKUP_VIRUSTOTAL_TIMEOUT'))
        
        if os.getenv('THREATLOOKUP_VIRUSTOTAL_ENABLED'):
            if 'virustotal' not in env_config:
                env_config['virustotal'] = {}
            env_config['virustotal']['enabled'] = os.getenv('THREATLOOKUP_VIRUSTOTAL_ENABLED').lower() in ('true', '1', 'yes')
        
        # Claude configuration
        if os.getenv('THREATLOOKUP_CLAUDE_API_KEY'):
            env_config['claude'] = {
                'api_key': os.getenv('THREATLOOKUP_CLAUDE_API_KEY'),
                'enabled': True
            }
        
        if os.getenv('THREATLOOKUP_CLAUDE_MODEL'):
            if 'claude' not in env_config:
                env_config['claude'] = {}
            env_config['claude']['model'] = os.getenv('THREATLOOKUP_CLAUDE_MODEL')
        
        if os.getenv('THREATLOOKUP_CLAUDE_TIMEOUT'):
            if 'claude' not in env_config:
                env_config['claude'] = {}
            env_config['claude']['timeout'] = int(os.getenv('THREATLOOKUP_CLAUDE_TIMEOUT'))
        
        if os.getenv('THREATLOOKUP_CLAUDE_ENABLED'):
            if 'claude' not in env_config:
                env_config['claude'] = {}
            env_config['claude']['enabled'] = os.getenv('THREATLOOKUP_CLAUDE_ENABLED').lower() in ('true', '1', 'yes')
        
        return env_config
    
    def setup_interactive(self) -> ThreatLookupConfig:
        """Interactive setup for first-time configuration."""
        print("🔧 ThreatLookup Configuration Setup")
        print("=" * 40)
        
        # Start with default config
        config = ThreatLookupConfig()
        
        # OTX setup
        print("\n📡 OpenThreatExchange (OTX) Configuration")
        print("Get your API key at: https://otx.alienvault.com/")
        
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
        
        # VirusTotal setup
        print("\n🛡️  VirusTotal Configuration")
        print("Get your API key at: https://www.virustotal.com/gui/my-apikey")
        
        if not config.virustotal.api_key:
            api_key = input("Enter your VirusTotal API key (or press Enter to skip): ").strip()
            if api_key:
                config.virustotal.api_key = api_key
                config.virustotal.enabled = True
                print("✅ VirusTotal integration enabled")
            else:
                config.virustotal.enabled = False
                print("⚠️  VirusTotal integration disabled")
        else:
            print(f"✅ VirusTotal API key already configured")
            enable = input("Enable VirusTotal integration? (y/N): ").strip().lower()
            if enable in ('y', 'yes'):
                config.virustotal.enabled = True
            else:
                config.virustotal.enabled = False
        
        # Claude setup
        print("\n🤖 Claude AI Configuration")
        print("Get your API key at: https://console.anthropic.com/")
        
        if not config.claude.api_key:
            api_key = input("Enter your Claude API key (or press Enter to skip): ").strip()
            if api_key:
                config.claude.api_key = api_key
                config.claude.enabled = True
                print("✅ Claude AI analysis enabled")
            else:
                config.claude.enabled = False
                print("⚠️  Claude AI analysis disabled")
        else:
            print(f"✅ Claude API key already configured")
            enable = input("Enable Claude AI analysis? (y/N): ").strip().lower()
            if enable in ('y', 'yes'):
                config.claude.enabled = True
            else:
                config.claude.enabled = False
        
        # Save configuration
        self.save_config(config)
        print(f"\n💾 Configuration saved to: {self.config_file}")
        
        return config


def get_config() -> ThreatLookupConfig:
    """Get the current configuration."""
    manager = ConfigManager()
    return manager.load_config()