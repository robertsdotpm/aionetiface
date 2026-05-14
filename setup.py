# Retained for tools that do not yet read pyproject.toml.
from setuptools import setup, find_packages
from os import path


here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

install_reqs = [
    "ntplib",
    "ecdsa",
    "netifaces; platform_system != 'Windows'",
    "pyroute2; platform_system == 'Linux'",
    "winregistry; platform_system == 'Windows'",
]

setup(
    version="0.0.20",
    name="aionetiface",
    description="Asynchronous networking library for IP interface and address management",
    keywords="networking, async, asyncio, interface, IP, NIC, STUN",
    long_description_content_type="text/markdown",
    long_description=long_description,
    url="http://github.com/robertsdotpm/aionetiface",
    author="Matthew Roberts",
    author_email="matthew@roberts.pm",
    license="public domain",
    package_dir={"": "src"},
    packages=find_packages(where="src", exclude=("tests", "docs")),
    include_package_data=True,
    python_requires=">=3.5",
    install_requires=install_reqs,
    classifiers=[
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
    ],
)
