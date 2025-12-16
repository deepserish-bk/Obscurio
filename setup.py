from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="obscurio",
    version="1.0.0",
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
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "obscurio=obscurio:main",
        ],
    },
)
