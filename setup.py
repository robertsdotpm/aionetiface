# Python version 3.5 and up.
from setuptools import setup, find_packages
from codecs import open
from os import path
import sys


here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

install_reqs = ["ntplib", "ecdsa"]
if sys.platform != "win32":
    install_reqs += ["netifaces"]
    if sys.platform != "darwin":
        install_reqs += ["pyroute2"]
else:
    install_reqs += ["winregistry"]

setup(
    version='0.0.7',
    name='aionetiface',
    description='Asynchronous networking library ',
    keywords=('test, python'),
    long_description_content_type="text/markdown",
    long_description=long_description,
    url='http://github.com/robertsdotpm/aionetiface',
    author='Matthew Roberts',
    author_email='matthew@roberts.pm',
    license='public domain',
    package_dir={"": "src"},
    packages=find_packages(where="src", exclude=('tests', 'docs')),
    include_package_data=True,
    install_requires=install_reqs,
    classifiers=[
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 3'
    ],
)
