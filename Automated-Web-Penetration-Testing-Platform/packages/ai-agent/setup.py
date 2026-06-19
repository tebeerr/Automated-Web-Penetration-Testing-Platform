from setuptools import find_packages, setup

setup(
    name="sentinel-ai-agent",
    version="0.1.0",
    description="LLM-based post-processing for scan findings.",
    packages=find_packages(),
    python_requires=">=3.11",
    install_requires=[
        "anthropic>=0.39",
        "openai>=1.50",
        "pydantic>=2.9",
    ],
)
