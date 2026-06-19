from setuptools import find_packages, setup

setup(
    name="sentinel-report-gen",
    version="0.1.0",
    description="PDF / HTML report builder for Sentinel scans.",
    packages=find_packages(),
    python_requires=">=3.11",
    install_requires=[
        "jinja2>=3.1",
        "weasyprint>=62.3",
    ],
)
