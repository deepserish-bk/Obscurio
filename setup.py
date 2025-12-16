from setuptools import setup, find_packages
import os

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

# Get version from code or use default
version = "1.0.0"

setup(
    name="obscurio",
    version=version,
    author="Your Name",
    author_email="your.email@example.com",
    description="A secure local password manager with AES-GCM encryption",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/deepserish-bk/Obscurio",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security :: Cryptography",
        "Development Status :: 4 - Beta",
        "Intended Audience :: End Users/Desktop",
        "Natural Language :: English",
    ],
    python_requires=">=3.8",
    install_requires=[
        "cryptography>=41.0.0",
        "pyperclip>=1.8.2",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "black>=23.0.0",
            "mypy>=1.5.0",
        ],
        "gui": [
            "PySimpleGUI>=4.60.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "obscurio=obscurio:main",
        ],
    },
    include_package_data=True,
    keywords="password-manager security encryption cryptography",
    project_urls={
        "Bug Reports": "https://github.com/deepserish-bk/Obscurio/issues",
        "Source": "https://github.com/deepserish-bk/Obscurio",
    },
)
