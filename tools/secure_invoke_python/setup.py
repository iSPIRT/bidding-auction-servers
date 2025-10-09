#!/usr/bin/env python3
"""Setup script for secure-invoke package."""

import os
import subprocess
from pathlib import Path
from setuptools import setup, find_packages
from setuptools.command.build_py import build_py


class BuildProtoCommand(build_py):
    """Custom build command to compile protobuf files."""
    
    def run(self):
        """Compile protobuf files before building package."""
        proto_dir = Path(__file__).parent / 'secure_invoke' / 'protos'
        proto_files = list(proto_dir.glob('*.proto'))
        
        if proto_files:
            print("Compiling protobuf files...")
            for proto_file in proto_files:
                cmd = [
                    'python', '-m', 'grpc_tools.protoc',
                    f'--proto_path={proto_dir}',
                    f'--python_out={proto_dir}',
                    f'--grpc_python_out={proto_dir}',
                    str(proto_file)
                ]
                print(f"Running: {' '.join(cmd)}")
                subprocess.check_call(cmd)
            
            # Fix imports in generated files
            for pb_file in proto_dir.glob('*_pb2*.py'):
                self._fix_imports(pb_file)
        
        super().run()
    
    def _fix_imports(self, file_path):
        """Fix relative imports in generated protobuf files."""
        content = file_path.read_text()
        
        # Fix imports to be relative within the package
        import_fixes = [
            ('import bidding_auction_servers_pb2', 'from . import bidding_auction_servers_pb2'),
            ('import generate_bid_pb2', 'from . import generate_bid_pb2'),
            ('import logger_pb2', 'from . import logger_pb2'),
        ]
        
        for old, new in import_fixes:
            content = content.replace(old, new)
        
        file_path.write_text(content)


# Read the long description from README
long_description = ""
readme_path = Path(__file__).parent / 'README.md'
if readme_path.exists():
    long_description = readme_path.read_text()

setup(
    name='secure-invoke',
    version='1.0.0',
    description='Python SDK for secure invoke operations with BFE/SFE services',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Privacy Sandbox',
    author_email='',
    url='https://github.com/privacysandbox/bidding-auction-servers',
    packages=find_packages(),
    package_data={
        'secure_invoke': ['protos/*.proto'],
    },
    include_package_data=True,
    python_requires='>=3.8',
    install_requires=[
        'pyhpke>=0.3.0',
        'requests>=2.31.0',
        'protobuf>=4.23.0',
        'grpcio>=1.54.0',
        'grpcio-tools>=1.54.0',
        'cryptography>=41.0.0',
    ],
    entry_points={
        'console_scripts': [
            'secure-invoke=secure_invoke.cli:main',
        ],
    },
    cmdclass={
        'build_py': BuildProtoCommand,
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
    ],
)

