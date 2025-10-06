# ThreatLookup

A comprehensive Python-based threat intelligence tool that analyzes domains using multiple threat intelligence sources and AI-powered analysis. ThreatLookup provides detailed threat assessments with actionable recommendations for security teams.

## 🚀 Features

- **Multi-Source Threat Intelligence**: Integrates OpenThreatExchange (OTX) and VirusTotal APIs
- **AI-Powered Analysis**: Claude AI provides sophisticated threat analysis and recommendations
- **Domain Analysis**: Comprehensive WHOIS-based threat assessment
- **Rich Output**: Beautiful console output with detailed threat intelligence
- **Multiple Output Formats**: Console, table, and JSON output options
- **Configurable**: Easy setup for API keys and service configuration

## 🔧 Installation

1. Clone the repository:
```bash
git clone https://github.com/threatlookup/threatlookup.git
cd threatlookup
```

2. Create a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Install the package:
```bash
pip install -e .
```

## ⚙️ Configuration

### Initial Setup

Run the interactive configuration setup:

```bash
threatlookup-config
```

This will guide you through setting up:
- **OpenThreatExchange (OTX) API**: Get your key at https://otx.alienvault.com/
- **VirusTotal API**: Get your key at https://www.virustotal.com/gui/my-apikey
- **Claude AI API**: Get your key at https://console.anthropic.com/

### Environment Variables

You can also configure using environment variables:

```bash
# OTX Configuration
export THREATLOOKUP_OTX_API_KEY="your_otx_api_key"
export THREATLOOKUP_OTX_ENABLED="true"

# VirusTotal Configuration
export THREATLOOKUP_VIRUSTOTAL_API_KEY="your_virustotal_api_key"
export THREATLOOKUP_VIRUSTOTAL_ENABLED="true"

# Claude AI Configuration
export THREATLOOKUP_CLAUDE_API_KEY="your_claude_api_key"
export THREATLOOKUP_CLAUDE_ENABLED="true"
```

### Configuration File

Configuration is stored in `~/.threatlookup/config.json`:

```json
{
  "otx": {
    "api_key": "your_otx_api_key",
    "enabled": true
  },
  "virustotal": {
    "api_key": "your_virustotal_api_key", 
    "enabled": true
  },
  "claude": {
    "api_key": "your_claude_api_key",
    "enabled": true
  }
}
```

## 📖 Usage

### Basic Domain Analysis

Analyze any domain for threat indicators:

```bash
threatlookup google.com
threatlookup suspicious-domain.com
threatlookup 29kgfx.ink
```

### Output Formats

```bash
# Detailed output (default)
threatlookup example.com

# Table format
threatlookup example.com --output table

# JSON format
threatlookup example.com --output json

# Verbose output
threatlookup example.com --verbose
```

### Testing Configuration

Test your API connections:

```bash
threatlookup-test
```

## 🔍 Threat Intelligence Sources

### OpenThreatExchange (OTX)
- **Community-driven threat intelligence**
- **Pulse data**: Threat campaigns and indicators
- **Malware families**: Associated malware families
- **Attack types**: Specific attack classifications

### VirusTotal
- **Multi-engine scanning**: 95+ security engines
- **Reputation scoring**: Domain reputation analysis
- **Categories**: Domain classification and categorization
- **Detection rates**: Malicious detection percentages

### Claude AI Analysis
- **Executive summaries**: Concise threat level overviews
- **Threat classification**: Primary threat types and confidence
- **Risk assessment**: Overall risk levels with key factors
- **Technical analysis**: Registration patterns and intelligence correlation
- **Actionable recommendations**: Specific remediation steps

## 📊 Example Output

### Clean Domain Analysis

```bash
$ threatlookup google.com

Threat Analysis for domain: google.com
============================================================
              Domain Information               
┏━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┓
┃ Property                ┃ Value             ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━┩
│ Domain                  │ google.com        │
│ Registration Date       │ 1997-09-15        │
│ Days Since Registration │ 10247             │
│ Country                 │ US                │
│ Registrar               │ MarkMonitor, Inc. │
└─────────────────────────┴───────────────────┘

OTX Threat Intelligence:
┏━━━━━━━━━━━━━━┳━━━━━━━━┓
┃ Property     ┃ Value  ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━┩
│ Malicious    │ No     │
│ Threat Score │ 0.0/10 │
│ Pulse Count  │ 0      │
│ Confidence   │ 80.0%  │
└──────────────┴────────┘

VirusTotal Intelligence:
┏━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Property          ┃ Value                                                    ┃
┡━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Malicious         │ No                                                       │
│ Detection Engines │ 95                                                       │
│ Malicious Engines │ 0                                                        │
│ Reputation        │ 646                                                      │
│ Reputation Status │ Positive                                                 │
└───────────────────┴──────────────────────────────────────────────────────────┘

Claude AI Analysis:
# Threat Intelligence Analysis: google.com

## 1. Summary
This domain represents Google's legitimate primary domain with extremely low 
risk indicators across all assessment categories...

## 2. Threat Type and Confidence Level
- **Threat Type:** None detected - Legitimate domain
- **Confidence Level:** Very High (90%)
- **Classification:** Benign/Trusted

## 3. Risk Level: **LOW**

## 4. Recommended Next Steps
1. **Whitelist Domain:** Add to organizational allow-lists...
2. **Monitor for Typosquatting:** Actively monitor for similar domains...
```

### Malicious Domain Analysis

```bash
$ threatlookup 29kgfx.ink

Threat Analysis for domain: 29kgfx.ink
============================================================
                        Domain Information                         
┏━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Property                ┃ Value                                 ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Domain                  │ 29kgfx.ink                            │
│ Registration Date       │ 2025-05-21                            │
│ Days Since Registration │ 137                                   │
│ Country                 │ HK                                    │
│ Registrar               │ Domain International Services Limited │
└─────────────────────────┴───────────────────────────────────────┘

OTX Threat Intelligence:
┏━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Property     ┃ Value                         ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Malicious    │ Yes                           │
│ Threat Score │ 2.4/10                        │
│ Pulse Count  │ 1                             │
│ Attack Types │ phishing &  scam domain names │
└──────────────┴───────────────────────────────┘

VirusTotal Intelligence:
┏━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Property          ┃ Value                   ┃
┡━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Malicious         │ Yes                     │
│ Detection Engines │ 95                      │
│ Malicious Engines │ 2                       │
│ Categories        │ Spam (alphaMountain.ai) │
└───────────────────┴─────────────────────────┘

Claude AI Analysis:
# Threat Intelligence Analysis: 29kgfx.ink

## 1. Summary
The domain 29kgfx.ink is a newly registered (137 days old) Hong Kong-based 
domain flagged by both OTX and VirusTotal as malicious...

## 2. Threat Type and Confidence Level
- **Threat Type:** Phishing & Scam Domain, Spam Distribution
- **Confidence Level:** Medium-High (70%)

## 3. Risk Level: **MEDIUM**

## 4. Recommended Next Steps
1. **Immediate Blocking:** Add domain to organizational blocklists...
2. **Email Security Review:** Search mail logs for any emails...
3. **Threat Hunting:** Conduct retroactive search across security logs...
```

## 🏗️ Project Structure
