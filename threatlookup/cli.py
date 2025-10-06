"""Command-line interface for ThreatLookup."""

import asyncio
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from .domain_analyzer import DomainAnalyzer
from .ioc_detector import IOCDetector, IOCType
from .models import ThreatLevel
from .config import ConfigManager


console = Console()


@click.command()
@click.argument('ioc')
@click.option('--output', '-o', type=click.Choice(['table', 'json', 'detailed']), 
              default='detailed', help='Output format')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.version_option(version="0.1.0")
def cli(ioc: str, output: str, verbose: bool):
    """ThreatLookup - Analyze domains, IPs, emails, files, and file hashes for threat indicators.
    
    IOC can be:
    - Domain: example.com, google.com
    - IP Address: 192.168.1.1, 2001:db8::1
    - Email: user@example.com
    - File Path: /path/to/file.exe, C:\\Windows\\file.dll
    - File Hash: a1b2c3d4e5f6... (MD5, SHA1, SHA256, SHA512)
    """
    asyncio.run(_analyze_ioc(ioc, output, verbose))


async def _analyze_ioc(ioc: str, output: str, verbose: bool):
    """Analyze IOC and display results."""
    try:
        # Detect IOC type
        detector = IOCDetector()
        ioc_type = detector.detect_ioc_type(ioc)
        
        if ioc_type == IOCType.UNKNOWN:
            console.print(f"[bold red]Error: Unable to determine IOC type for '{ioc}'[/bold red]")
            console.print("[yellow]Supported IOC types:[/yellow]")
            console.print("  • Domain: example.com, google.com")
            console.print("  • IP Address: 192.168.1.1, 2001:db8::1")
            console.print("  • Email: user@example.com")
            console.print("  • File Path: /path/to/file.exe, C:\\Windows\\file.dll")
            console.print("  • File Hash: a1b2c3d4e5f6... (MD5, SHA1, SHA256, SHA512)")
            raise click.Abort()
        
        # Clean the input based on IOC type
        clean_ioc = detector.get_clean_input(ioc, ioc_type)
        
        # Route to appropriate analyzer
        if ioc_type == IOCType.DOMAIN:
            await _analyze_domain(clean_ioc, output, verbose, ioc_type)
        elif ioc_type == IOCType.IP_ADDRESS:
            await _analyze_ip_address(clean_ioc, output, verbose, ioc_type)
        elif ioc_type == IOCType.EMAIL:
            await _analyze_email(clean_ioc, output, verbose, ioc_type)
        elif ioc_type == IOCType.FILE_PATH:
            await _analyze_file_path(clean_ioc, output, verbose, ioc_type)
        elif ioc_type == IOCType.FILE_HASH:
            await _analyze_file_hash(clean_ioc, output, verbose, ioc_type)
            
    except ValueError as e:
        console.print(f"[bold red]Error: {e}[/bold red]")
        raise click.Abort()
    except Exception as e:
        console.print(f"[bold red]Unexpected error: {e}[/bold red]")
        if verbose:
            console.print_exception()
        raise click.Abort()


async def _analyze_domain(domain: str, output: str, verbose: bool, ioc_type: IOCType):
    """Analyze domain and display results."""
    try:
        analyzer = DomainAnalyzer()
        
        with console.status(f"[bold green]Analyzing {ioc_type.value}: {domain}..."):
            analysis = await analyzer.analyze_domain(domain)
        
        if output == 'json':
            _display_json_output(analysis, ioc_type)
        elif output == 'table':
            _display_table_output(analysis, ioc_type)
        else:
            _display_detailed_output(analysis, verbose, ioc_type)
            
    except ValueError as e:
        console.print(f"[bold red]Error: {e}[/bold red]")
        raise click.Abort()
    except Exception as e:
        console.print(f"[bold red]Unexpected error: {e}[/bold red]")
        if verbose:
            console.print_exception()
        raise click.Abort()


async def _analyze_ip_address(ip_address: str, output: str, verbose: bool, ioc_type: IOCType):
    """Analyze IP address and display results."""
    console.print(f"[bold yellow]IP Address analysis not yet implemented for: {ip_address}[/bold yellow]")
    console.print("[yellow]This feature will be added in a future update.[/yellow]")


async def _analyze_email(email: str, output: str, verbose: bool, ioc_type: IOCType):
    """Analyze email address and display results."""
    console.print(f"[bold yellow]Email analysis not yet implemented for: {email}[/bold yellow]")
    console.print("[yellow]This feature will be added in a future update.[/yellow]")


async def _analyze_file_path(file_path: str, output: str, verbose: bool, ioc_type: IOCType):
    """Analyze file path and display results."""
    console.print(f"[bold yellow]File path analysis not yet implemented for: {file_path}[/bold yellow]")
    console.print("[yellow]This feature will be added in a future update.[/yellow]")


async def _analyze_file_hash(file_hash: str, output: str, verbose: bool, ioc_type: IOCType):
    """Analyze file hash and display results."""
    console.print(f"[bold yellow]File hash analysis not yet implemented for: {file_hash}[/bold yellow]")
    console.print("[yellow]This feature will be added in a future update.[/yellow]")


def _display_detailed_output(analysis, verbose: bool, ioc_type: IOCType):
    """Display detailed analysis results."""
    # Header
    console.print(f"\n[bold blue]Threat Analysis for {ioc_type.value}: {analysis.domain}[/bold blue]")
    console.print("=" * 60)
    
    
    # Domain Information
    info_table = Table(title="Domain Information", show_header=True, header_style="bold magenta")
    info_table.add_column("Property", style="cyan")
    info_table.add_column("Value", style="white")
    
    info_table.add_row("Domain", analysis.domain)
    info_table.add_row("Registration Date", 
                      analysis.registration_date.strftime("%Y-%m-%d") if analysis.registration_date else "Unknown")
    info_table.add_row("Days Since Registration", 
                      str(analysis.days_since_registration) if analysis.days_since_registration is not None else "Unknown")
    info_table.add_row("Country", analysis.country or "Unknown")
    info_table.add_row("Registrar", analysis.registrar or "Unknown")
    
    console.print(info_table)
    
    
    # OTX Intelligence Data
    if analysis.otx_data:
        console.print("\n[bold cyan]OTX Threat Intelligence:[/bold cyan]")
        otx_table = Table(show_header=True, header_style="bold cyan")
        otx_table.add_column("Property", style="cyan")
        otx_table.add_column("Value", style="white")
        
        otx_table.add_row("Malicious", "Yes" if analysis.otx_data["is_malicious"] else "No")
        otx_table.add_row("Threat Score", f"{analysis.otx_data['threat_score']:.1f}/10")
        otx_table.add_row("Pulse Count", str(analysis.otx_data["pulse_count"]))
        otx_table.add_row("Confidence", f"{analysis.otx_data['confidence']:.1%}")
        
        if analysis.otx_data["malware_families"]:
            otx_table.add_row("Malware Families", ", ".join(analysis.otx_data["malware_families"][:3]))
        if analysis.otx_data["attack_types"]:
            otx_table.add_row("Attack Types", ", ".join(analysis.otx_data["attack_types"][:3]))
        
        console.print(otx_table)
    
    # VirusTotal Intelligence Data
    if analysis.virustotal_data:
        console.print("\n[bold green]VirusTotal Intelligence:[/bold green]")
        vt_table = Table(show_header=True, header_style="bold green")
        vt_table.add_column("Property", style="green")
        vt_table.add_column("Value", style="white")
        
        # Basic threat information
        vt_table.add_row("Malicious", "Yes" if analysis.virustotal_data["is_malicious"] else "No")
        vt_table.add_row("Threat Score", f"{analysis.virustotal_data['threat_score']:.1f}/10")
        vt_table.add_row("Detection Engines", str(analysis.virustotal_data["detection_engines"]))
        vt_table.add_row("Malicious Engines", str(analysis.virustotal_data["malicious_engines"]))
        vt_table.add_row("Reputation", str(analysis.virustotal_data["reputation"]))
        vt_table.add_row("Confidence", f"{analysis.virustotal_data['confidence']:.1%}")
        
        # Additional detailed information
        if analysis.virustotal_data["categories"]:
            categories = ", ".join(analysis.virustotal_data["categories"][:5])  # Show more categories
            vt_table.add_row("Categories", categories)
        
        if analysis.virustotal_data["last_analysis_date"]:
            vt_table.add_row("Last Analysis", analysis.virustotal_data["last_analysis_date"][:10])
        
        # Show engine breakdown if available
        if analysis.virustotal_data["detection_engines"] > 0:
            malicious_pct = (analysis.virustotal_data["malicious_engines"] / analysis.virustotal_data["detection_engines"]) * 100
            vt_table.add_row("Malicious %", f"{malicious_pct:.1f}%")
        
        # Show reputation interpretation
        reputation = analysis.virustotal_data["reputation"]
        if reputation < 0:
            vt_table.add_row("Reputation Status", "[red]Negative[/red]")
        elif reputation > 0:
            vt_table.add_row("Reputation Status", "[green]Positive[/green]")
        else:
            vt_table.add_row("Reputation Status", "[yellow]Neutral[/yellow]")
        
        console.print(vt_table)
    
    # Claude AI Analysis
    if analysis.claude_analysis:
        console.print("\n[bold blue]Claude AI Analysis:[/bold blue]")
        claude_text = analysis.claude_analysis.get("analysis", "")
        if claude_text:
            # Split the analysis into sections for better display
            sections = claude_text.split("\n\n")
            for section in sections:
                if section.strip():
                    console.print(f"[blue]{section.strip()}[/blue]")
                    console.print()  # Add spacing between sections
        else:
            console.print("[yellow]No Claude analysis available[/yellow]")
    
    # Remediation Steps
    if analysis.remediation_steps:
        console.print("\n[bold red]Recommended Actions:[/bold red]")
        for i, step in enumerate(analysis.remediation_steps, 1):
            console.print(f"  {i}. {step}")
    
    # Verbose output
    if verbose and hasattr(analysis, 'raw_whois_data'):
        console.print(f"\n[bold yellow]Raw WHOIS Data:[/bold yellow]")
        console.print(analysis.raw_whois_data)


def _display_table_output(analysis, ioc_type: IOCType):
    """Display analysis results in table format."""
    table = Table(title=f"Threat Analysis: {analysis.domain}")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white")
    
    table.add_row("Overall Risk Score", f"{analysis.risk_score.overall_score:.1f}/10")
    table.add_row("Threat Level", analysis.risk_score.threat_level.value.upper())
    table.add_row("Registration Date", 
                 analysis.registration_date.strftime("%Y-%m-%d") if analysis.registration_date else "Unknown")
    table.add_row("Country", analysis.country or "Unknown")
    table.add_row("Randomized", "Yes" if analysis.is_randomized else "No")
    table.add_row("Confidence", f"{analysis.risk_score.confidence:.1%}")
    
    console.print(table)


def _display_json_output(analysis, ioc_type: IOCType):
    """Display analysis results in JSON format."""
    import json
    
    result = {
        "ioc_type": ioc_type.value,
        "domain": analysis.domain,
        "domain_info": {
            "registration_date": analysis.registration_date.isoformat() if analysis.registration_date else None,
            "days_since_registration": analysis.days_since_registration,
            "country": analysis.country,
            "registrar": analysis.registrar
        },
        "otx_intelligence": analysis.otx_data,
        "virustotal_intelligence": analysis.virustotal_data,
        "claude_analysis": analysis.claude_analysis,
        "remediation_steps": analysis.remediation_steps
    }
    
    console.print(json.dumps(result, indent=2))


def _get_risk_color(threat_level: ThreatLevel) -> str:
    """Get color for threat level."""
    color_map = {
        ThreatLevel.LOW: "green",
        ThreatLevel.MEDIUM: "yellow",
        ThreatLevel.HIGH: "red",
        ThreatLevel.CRITICAL: "bright_red"
    }
    return color_map.get(threat_level, "white")


if __name__ == '__main__':
    cli()
