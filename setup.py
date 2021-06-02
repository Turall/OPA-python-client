"""
    OPA-python-client
    Python client integrates with   Open Policy Agent (OPA) service

"""

import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="OPA-python-client",
    version="1.3.1",
    author="Tural Muradov",
    author_email="tural_m@hotmail.com",
    description="Client for connection to the OPA service",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Turall/OPA-python-client.git",
    license="MIT",
    install_requires=[
        "user-agent>=0.1.9",
        "requests>=2.5.4.1",
        "urllib3==1.26.5",
        "certifi>=2019.11.28",
    ],
    packages=setuptools.find_packages(),
    classifiers=[
        "Intended Audience :: Developers",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3 :: Only",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)
