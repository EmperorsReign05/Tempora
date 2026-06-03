import os
from setuptools import setup, find_packages

with open(os.path.join(os.path.dirname(__file__), "README.md"), "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="tempora-cli",
    version="2.0.5",
    description="Tempora: Automated Log Integrity Monitor and Forensic Dashboard",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Mohammad Alman Farooqui",
    packages=find_packages(),
    install_requires=[
        "PyYAML>=6.0",
    ],
    extras_require={
        "aws": ["boto3>=1.34.0"],
    },
    entry_points={
        "console_scripts": [
            "tempora=tempora.cli:main",
        ]
    },
    python_requires=">=3.7",
)
