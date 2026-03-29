from setuptools import setup

setup(
    name="tempora-forensics",
    version="1.0.0",
    description="Tempora: Automated Log Integrity Monitor and Forensic Dashboard",
    author="Mohammad Alman Farooqui",
    py_modules=["integrity_check"],
    entry_points={
        "console_scripts": [
            "tempora=integrity_check:main",
        ]
    },
    python_requires=">=3.7",
)
