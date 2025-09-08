"""
Setup script for pfSense Configuration Management CLI Tool
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the contents of the README file
this_directory = Path(__file__).parent
long_description = ""

# Read requirements from requirements.txt
def read_requirements(filename):
    """Read requirements from requirements.txt file."""
    requirements = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Remove version constraints for setup.py compatibility
                    requirement = line.split('>=')[0].split('==')[0].split('<')[0]
                    requirements.append(requirement)
    except FileNotFoundError:
        pass
    return requirements

# Core requirements (excluding development dependencies)
install_requires = [
    'click>=8.1.0',
    'pydantic>=2.0.0',
    'pyyaml>=6.0',
    'aiohttp>=3.8.0',
    'requests>=2.28.0',
    'jinja2>=3.1.0',
    'tabulate>=0.9.0',
    'colorama>=0.4.6',
    'urllib3>=1.26.0',
    'cryptography>=40.0.0',
]

# Development dependencies
dev_requires = [
    'pytest>=7.0.0',
    'pytest-asyncio>=0.21.0',
    'pytest-cov>=4.0.0',
    'black>=23.0.0',
    'flake8>=6.0.0',
    'mypy>=1.0.0',
]

# Documentation dependencies
docs_requires = [
    'mkdocs>=1.4.0',
    'mkdocs-material>=9.0.0',
]

setup(
    name="pfsense-cli",
    version="1.0.0",
    author="pfSense CLI Tool",
    author_email="admin@example.com",
    description="Professional pfSense automation and configuration management CLI tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/your-org/pfsense-cli",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: System :: Networking",
        "Topic :: System :: Systems Administration",
        "Topic :: Utilities",
    ],
    python_requires=">=3.8",
    install_requires=install_requires,
    extras_require={
        'dev': dev_requires,
        'docs': docs_requires,
        'all': dev_requires + docs_requires,
    },
    entry_points={
        'console_scripts': [
            'pfsense-cli=pfsense_cli.cli.main:main',
            'pfsense=pfsense_cli.cli.main:main',  # Short alias
        ],
    },
    include_package_data=True,
    package_data={
        'pfsense_cli': [
            'config/templates/*.yaml',
            'config/templates/*.yml',
        ],
    },
    project_urls={
        "Bug Reports": "https://github.com/your-org/pfsense-cli/issues",
        "Source": "https://github.com/your-org/pfsense-cli",
        "Documentation": "https://pfsense-cli.readthedocs.io/",
    },
    keywords="pfsense firewall automation cli network management vpn dhcp vlan",
    zip_safe=False,
)