#!/usr/bin/env python3
"""
Setup script for secure_invoke Python package.

This package provides Python bindings for the SecureInvoke cryptographic library
used in Privacy Sandbox bidding and auction systems.
"""

from setuptools import setup, find_packages, Extension
from setuptools.command.build_ext import build_ext
try:
    from setuptools.command.build import build
except ImportError:
    from distutils.command.build import build
try:
    from setuptools.command.install import install
except ImportError:
    from distutils.command.install import install
import os
import subprocess
import sys
from pathlib import Path

class BazelBuildLibs:
    """Mixin class that provides Bazel library building functionality."""
    
    _libs_built = False  # Class variable to track if libraries have been built
    
    def build_bazel_libs(self):
        """Build the C++ libraries using Bazel."""
        # Always clean existing .so files from lib directory to avoid permission issues
        # Use absolute path to source directory to avoid build directory confusion
        project_root = Path(__file__).parent.parent.parent.parent.absolute()
        lib_dir = project_root / "tools/secure_invoke/python/secure_invoke_crypto/lib"
        print(f"Checking lib directory: {lib_dir}")
        print(f"Lib directory exists: {lib_dir.exists()}")
        
        if lib_dir.exists():
            import glob
            so_pattern = str(lib_dir / "*.so")
            so_files = glob.glob(so_pattern)
            print(f"Cleaning existing .so files from: {lib_dir}")
            print(f"Looking for pattern: {so_pattern}")
            print(f"Found .so files: {so_files}")
            
            if so_files:
                for so_file in so_files:
                    try:
                        os.remove(so_file)
                        print(f"Removed: {so_file}")
                    except OSError as e:
                        print(f"Warning: Could not remove {so_file}: {e}")
            else:
                print("No .so files found to clean")
        else:
            print("Lib directory does not exist, will be created during build")
        
        # Skip actual Bazel build if libraries are already built in this session
        if BazelBuildLibs._libs_built:
            print("Bazel build already completed in this session, skipping build step...")
            return
        
        # Reset the built flag for testing
        BazelBuildLibs._libs_built = False
        
        # Get the project root (assuming we're in tools/secure_invoke/python)
        project_root = Path(__file__).parent.parent.parent.parent.absolute()
        original_cwd = os.getcwd()  # Save original directory
        
        print(f"Building C++ library from: {project_root}")
        
        # Build the shared libraries using Bazel
        try:
            os.chdir(project_root)
            # Build the main secure_invoke library
            subprocess.run([
                "./builders/tools/bazel-debian", "build", 
                "//tools/secure_invoke:libsecure_invoke.so"
            ], check=True)
            
            # Note: libcddl.so is built as part of main repository build
            
            # Copy the built library to the package lib directory (source directory)
            src_lib = project_root / "bazel-bin/tools/secure_invoke/libsecure_invoke.so"
            # Always use the source directory, not build directory
            source_dir = project_root / "tools/secure_invoke/python/secure_invoke_crypto/lib"
            dst_lib = source_dir / "libsecure_invoke.so"
            
            # Ensure lib directory exists
            dst_lib.parent.mkdir(parents=True, exist_ok=True)
            
            if src_lib.exists():
                import shutil
                shutil.copy2(src_lib, dst_lib)
                print(f"Copied library: {src_lib} -> {dst_lib}")
                
                # Also copy dependent libraries from external build
                cddl_src = project_root / "bazel-bin/external/cddl_lib/libcddl.so"
                if cddl_src.exists():
                    cddl_dst = source_dir / "libcddl.so"
                    shutil.copy2(cddl_src, cddl_dst)
                    print(f"Copied dependent library: {cddl_src} -> {cddl_dst}")
                else:
                    print(f"Warning: libcddl.so not found at {cddl_src}, package may need manual library setup")
                    print(f"Make sure the main repository has been built first with Bazel")
            else:
                raise FileNotFoundError(f"Built library not found: {src_lib}")
                
        except subprocess.CalledProcessError as e:
            print(f"Failed to build C++ library: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"Error during build: {e}")
            sys.exit(1)
        finally:
            # Always restore original working directory
            os.chdir(original_cwd)
        
        # Libraries built successfully
        BazelBuildLibs._libs_built = True

class BazelBuildExt(build_ext, BazelBuildLibs):
    """Custom build extension that uses Bazel to build the C++ library."""
    
    def run(self):
        """Build the C++ library using Bazel before building Python extensions."""
        self.build_bazel_libs()
        # Continue with normal extension building (if any)
        super().run()

class BazelBuild(build, BazelBuildLibs):
    """Custom build command that ensures Bazel libraries are built."""
    
    def run(self):
        """Build libraries then continue with normal build."""
        self.build_bazel_libs()
        super().run()

class BazelInstall(install, BazelBuildLibs):
    """Custom install command that ensures Bazel libraries are built."""
    
    def run(self):
        """Build libraries then continue with normal install."""
        self.build_bazel_libs()
        super().run()


# Read version from version file
def get_version():
    version_file = Path(__file__).parent / "secure_invoke_crypto" / "_version.py"
    if version_file.exists():
        with open(version_file) as f:
            exec(f.read())
            return locals()['__version__']
    return "0.1.0"

# Read long description from README
def get_long_description():
    readme_file = Path(__file__).parent / "README.md"
    if readme_file.exists():
        with open(readme_file, encoding='utf-8') as f:
            return f.read()
    return ""

setup(
    name="secure-invoke-crypto",
    version=get_version(),
    author="ispirt team",
    author_email="pavankad@gmail.com",
    description="Python cryptographic bindings for SecureInvoke library",
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
    url="https://github.com/ispirt/bidding-auction-servers",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.25.0",
        "typing-extensions>=3.7.4; python_version<'3.8'",
    ],
    extras_require={
        "dev": [
            "pytest>=6.0",
            "pytest-cov>=2.0",
            "black>=21.0",
            "flake8>=3.8",
            "mypy>=0.900",
        ],
        "async": [
            "aiohttp>=3.7.0",
        ],
    },
    package_data={
        "secure_invoke_crypto": [
            "lib/*.so",
            "src/*.cc",
            "src/*.h",
        ],
    },
    include_package_data=True,
    cmdclass={
        'build_ext': BazelBuildExt,
        'build': BazelBuild,
        'install': BazelInstall,
    },
    entry_points={
        "console_scripts": [
            "secure-invoke-test=secure_invoke_crypto.tests.test_encrypt_http:main",
            "secure-invoke-demo=secure_invoke_crypto.crypto:demo",
        ],
    },
    zip_safe=False,  # C extensions can't be loaded from zip files
)
