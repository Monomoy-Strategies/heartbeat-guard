from setuptools import setup, find_packages
import os

# Read the README file
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read version from __init__.py
def get_version():
    with open("heartbeat_guard/__init__.py", "r") as f:
        for line in f:
            if line.startswith("__version__"):
                return line.split('"')[1]
    return "1.0.0"

setup(
    name="heartbeat-guard",
    version=get_version(),
    author="Monomoy Strategies",
    author_email="bsifflard@monomoystrategies.com",
    description="Your AI Agent's Security Watchdog - Comprehensive security monitoring for OpenClaw agents",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Monomoy-Strategies/heartbeat-guard",
    project_urls={
        "Homepage": "https://heartbeatguard.com",
        "Documentation": "https://heartbeatguard.com/docs",
        "Bug Tracker": "https://github.com/Monomoy-Strategies/heartbeat-guard/issues",
        "Source Code": "https://github.com/Monomoy-Strategies/heartbeat-guard",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
    ],
    python_requires=">=3.9",
    install_requires=[
        "psutil>=5.8.0",
        "requests>=2.25.0",
        "cryptography>=3.4.0",
        "sqlite3-python",
    ],
    extras_require={
        "dev": [
            "pytest>=6.0",
            "black>=21.0",
            "flake8>=3.8",
            "mypy>=0.812",
        ],
        "telegram": [
            "python-telegram-bot>=13.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "heartbeat-guard=heartbeat_guard.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "heartbeat_guard": ["*.json", "*.md"],
    },
    keywords=[
        "security",
        "monitoring", 
        "ai",
        "agent",
        "openclaw",
        "threat-detection",
        "cybersecurity",
        "system-monitoring",
        "vulnerability-scanner"
    ],
    zip_safe=False,
)