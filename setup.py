from setuptools import setup, find_packages

setup(
    name="tempora-forensics",
    version="2.0.0",
    description="Tempora: Automated Log Integrity Monitor and Forensic Dashboard",
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
