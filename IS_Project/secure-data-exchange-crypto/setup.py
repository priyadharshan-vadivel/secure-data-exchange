from setuptools import setup, find_packages

setup(
    name="secure-data-exchange",
    version="1.0.0",
    description="Secure Data Exchange using Cryptographic Techniques",
    packages=find_packages("src"),
    package_dir={"": "src"},
    install_requires=["cryptography>=41.0.0"],
)
