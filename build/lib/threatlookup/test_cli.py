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
    
    console.print("\n[bold green]Configuration test complete![/bold green]")


if __name__ == '__main__':
    test()
