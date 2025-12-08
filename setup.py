from setuptools import setup, find_packages
import os

# Read README for long description
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read requirements
with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="wshawk",
    version="2.0.5",
    author="Regaan",
    description="Professional WebSocket security scanner with real vulnerability verification, session hijacking tests, and CVSS scoring",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/noobforanonymous/wshawk",
    packages=find_packages(exclude=["tests", "tests.*", "examples", "examples.*", "docs"]),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "wshawk=wshawk.__main__:cli",
            "wshawk-interactive=wshawk.interactive:cli",
            "wshawk-advanced=wshawk.advanced_cli:cli",
            "wshawk-defensive=wshawk.defensive_cli:cli",
        ],
    },
    include_package_data=True,
    package_data={
        "wshawk": [
            "payloads/*.txt",
            "payloads/**/*.json",
        ],
    },
    keywords="websocket security scanner penetration-testing bug-bounty vulnerability xss sqli session-hijacking cvss playwright oast waf-bypass",
    project_urls={
        "Bug Reports": "https://github.com/noobforanonymous/wshawk/issues",
        "Source": "https://github.com/noobforanonymous/wshawk",
        "Documentation": "https://github.com/noobforanonymous/wshawk/blob/main/README.md",
    },
)
