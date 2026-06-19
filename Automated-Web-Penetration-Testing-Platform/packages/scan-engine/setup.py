from setuptools import find_packages, setup

setup(
    name="sentinel-scan-engine",
    version="0.1.0",
    description="Pluggable scanner orchestrator (ZAP, Nuclei, Nmap, custom).",
    packages=find_packages(),
    python_requires=">=3.11",
    install_requires=[
        "aiohttp>=3.10",
        "pydantic>=2.9",
    ],
)
