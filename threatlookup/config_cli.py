"""Configuration CLI for ThreatLookup."""

import click
from .config import ConfigManager


@click.command()
def config():
    """Configure ThreatLookup settings and API keys."""
    manager = ConfigManager()
    manager.setup_interactive()


if __name__ == '__main__':
    config()
