from setuptools import setup, find_packages

setup(
    name="KeyTabExtract",
    version="1.0.0",
    author="KcanCurly",
    description="KeyTabExtract is a utility to help extract valuable information from Kerberos .keytab files, which may be used to authenticate Linux boxes to Kerberos. The script extracts information such as the realm, Service Principal, Encryption Type, and hashes (NTLM, AES-128, AES-256) with timestamps.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/KcanCurly/KeyTabExtract",
    packages=find_packages(),
    install_requires=[
        "colorama>=0.4.4",
    ],
    python_requires=">=3.6",
    entry_points={
        "console_scripts": [
            "keytabextract.py=src.keytabextract:main",  
        ],
    },
)