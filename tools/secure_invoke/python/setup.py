#!/usr/bin/env python3
"""
Setup script for secure-request CLI tool
"""

from setuptools import setup, find_packages
import os

# Read the README file for long description
def read_readme():
    readme_path = os.path.join(os.path.dirname(__file__), 'README.md')
    if os.path.exists(readme_path):
        with open(readme_path, 'r', encoding='utf-8') as f:
            return f.read()
    return "Secure Request CLI tool for secure request operations"

# Read version from secure_request_client
def get_version():
    version_path = os.path.join(os.path.dirname(__file__), 'secure_request_client', '_version.py')
    if os.path.exists(version_path):
        with open(version_path, 'r') as f:
            for line in f:
                if line.startswith('__version__'):
                    return line.split('=')[1].strip().strip('"\'')
    return "0.1.0"

setup(
    name="secure-request",
    version=get_version(),
    description="CLI tool for secure request operations with KMS and Offer services",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    author="iSPIRT DEPA Team",
    author_email="depa@ispirt.com",
    url="https://github.com/ispirt/depa-bidding-auction-servers",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        'secure_request_client': ['lib/*.so'],  # include your .so files
    },
    zip_safe=False,  # important for .so files
    install_requires=[
        'requests>=2.25.0',
        'urllib3>=1.26.0',
    ],
    python_requires=">=3.7",
    entry_points={
        'console_scripts': [
            'secure-request=secure_request_client.cli:main',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Topic :: Security :: Cryptography',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    keywords='security cryptography kms offer bidding auction',
    project_urls={
        'Bug Reports': 'https://github.com/ispirt/depa-bidding-auction-servers/issues',
        'Source': 'https://github.com/ispirt/depa-bidding-auction-servers',
    },
)
