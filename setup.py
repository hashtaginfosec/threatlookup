"""Setup script for ThreatLookup."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="threatlookup",
    version="0.1.0",
    author="ThreatLookup Team",
    author_email="team@threatlookup.com",
    description="A Python-based threat lookup tool using ML regression for threat ranking",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/threatlookup/threatlookup",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "python-whois>=0.8.0",
        "requests>=2.31.0",
        "pydantic>=2.5.0",
        "click>=8.1.7",
        "rich>=13.7.0",
    ],
    entry_points={
        "console_scripts": [
            "threatlookup=threatlookup.cli:cli",
            "threatlookup-config=threatlookup.config_cli:config",
            "threatlookup-test=threatlookup.test_cli:test",
        ],
    },
)
