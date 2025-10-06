"""Test CLI for ThreatLookup."""

import asyncio
import click
from rich.console import Console
from .otx_client import OTXClient

console = Console()


@click.command()
def test():
    """Test API connections and configuration."""
    asyncio.run(_test_connections())


async def _test_connections():
    """Test API connections and configuration."""
    console.print("[bold blue]Testing ThreatLookup Configuration[/bold blue]")
    console.print("=" * 50)
    
    # Test OTX connection
    console.print("\n📡 Testing OpenThreatExchange (OTX) API...")
    otx_client = OTXClient()
    
    if not otx_client.enabled:
        console.print("[yellow]⚠️  OTX API not configured or disabled[/yellow]")
        console.print("[yellow]Run 'threatlookup-config' to set up OTX integration[/yellow]")
    else:
        console.print("[green]✅ OTX API key configured[/green]")
        
        # Test connection
        console.print("Testing OTX API connection...")
        if await otx_client.test_connection():
            console.print("[green]✅ OTX API connection successful[/green]")
        else:
            console.print("[red]❌ OTX API connection failed[/red]")
            console.print("[yellow]Check your API key and internet connection[/yellow]")
    
        # Test VirusTotal connection
        console.print("\n🛡️  Testing VirusTotal API...")
        from .config import get_config
        config = get_config()
        
        if not config.virustotal.enabled or not config.virustotal.api_key:
            console.print("[yellow]⚠️  VirusTotal API not configured or disabled[/yellow]")
            console.print("[yellow]Run 'threatlookup-config' to set up VirusTotal integration[/yellow]")
        else:
            console.print("[green]✅ VirusTotal API key configured[/green]")
            console.print("[yellow]Note: VirusTotal API testing requires actual API calls[/yellow]")
            console.print("[yellow]VirusTotal integration will be tested during domain analysis[/yellow]")
        
        # Test Claude connection
        console.print("\n🤖 Testing Claude AI API...")
        from .claude_client import ClaudeClient
        claude_client = ClaudeClient()
        
        if not claude_client.enabled or not claude_client.api_key:
            console.print("[yellow]⚠️  Claude API not configured or disabled[/yellow]")
            console.print("[yellow]Run 'threatlookup-config' to set up Claude AI integration[/yellow]")
        else:
            console.print("[green]✅ Claude API key configured[/green]")
            console.print("[yellow]Note: Claude API testing requires actual API calls[/yellow]")
            console.print("[yellow]Claude AI integration will be tested during domain analysis[/yellow]")
    
    console.print("\n[bold green]Configuration test complete![/bold green]")


if __name__ == '__main__':
    test()
