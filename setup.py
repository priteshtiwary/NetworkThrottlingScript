"""Packaging for mac-network-throttle."""

from setuptools import find_packages, setup

with open("README.md", "r", encoding="utf-8") as handle:
    long_description = handle.read()

setup(
    name="mac-network-throttle",
    version="1.0.0",
    description="Turn a Mac into a network-throttling WiFi hotspot (pfctl + dnctl).",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(exclude=("tests", "tests.*")),
    python_requires=">=3.8",
    install_requires=[],
    extras_require={"dev": ["pytest>=7.0", "pytest-cov>=4.0"]},
    entry_points={
        "console_scripts": [
            "mac-throttle=throttle.cli:main",
        ],
    },
    classifiers=[
        "Environment :: MacOS X",
        "Operating System :: MacOS :: MacOS X",
        "Programming Language :: Python :: 3",
        "Topic :: System :: Networking",
    ],
)
