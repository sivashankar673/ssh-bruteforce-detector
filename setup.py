#!/usr/bin/env python3
"""
Setup script for SSH Brute Force Detection Tool
"""

from setuptools import setup, find_packages
import os

# Read the README file
def read_readme():
    """Read README.md file for long description"""
    readme_path = os.path.join(os.path.dirname(__file__), 'README.md')
    try:
        with open(readme_path, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        return "SSH Brute Force Detection Tool"

setup(
    name="ssh-bruteforce-detector",
    version="1.0.0",
    author="Security Team",
    author_email="security@example.com",
    description="A Python tool for detecting SSH brute force attacks in authentication logs",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/ssh-bruteforce-detector",
    py_modules=["bruteforce_detector"],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "Topic :: System :: Systems Administration",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: POSIX :: Linux",
        "Operating System :: Unix",
    ],
    keywords="ssh security brute-force detection cybersecurity log-analysis intrusion-detection",
    python_requires=">=3.6",
    install_requires=[
        # No external dependencies - uses only standard library
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "flake8>=5.0.0",
            "black>=22.0.0",
            "mypy>=1.0.0",
        ],
        "enhanced": [
            "colorama>=0.4.0",
            "tabulate>=0.9.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "bruteforce-detector=bruteforce_detector:main",
            "ssh-bruteforce-detector=bruteforce_detector:main",
        ],
    },
    project_urls={
        "Bug Reports": "https://github.com/yourusername/ssh-bruteforce-detector/issues",
        "Source": "https://github.com/yourusername/ssh-bruteforce-detector",
        "Documentation": "https://github.com/yourusername/ssh-bruteforce-detector/wiki",
    },
    include_package_data=True,
    zip_safe=False,
)
