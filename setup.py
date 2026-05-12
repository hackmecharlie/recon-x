# ============================================================
# RECON-X | setup.py
# Description: Package setup and entry point configuration
# ============================================================

from setuptools import setup, find_packages
from pathlib import Path

requirements = Path("requirements.txt").read_text().splitlines()

setup(
    name="recon-x",
    version="1.0.0",
    description="Production-ready CLI security reconnaissance tool",
    author="RECON-X Team",
    python_requires=">=3.10",
    packages=find_packages(),
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "recon-x=cli.main:app",
        ],
    },
    include_package_data=True,
    package_data={
        "reporting": ["templates/*.j2"],
        "config": ["*.yaml"],
    },
)
