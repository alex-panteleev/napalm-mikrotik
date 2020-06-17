import os
import sys
import codecs

from setuptools import setup, find_packages

__author__ = 'Juan Gomez <jgomez@phicus.es>'

# https://github.com/pypa/pip/blob/7ed5e12ae83ef90ac33be33555ea52f61457c1d2/setup.py#L11
def read(rel_path):
    here = os.path.abspath(os.path.dirname(__file__))
    # intentionally *not* adding an encoding option to open, See:
    #   https://github.com/pypa/virtualenv/issues/201#issuecomment-3145690
    with codecs.open(os.path.join(here, rel_path), 'r') as fp:
        return fp.read()

def parse_reqs(file_path):
    lines = read(file_path).splitlines()
    lines = map(str.strip, lines)
    lines = filter(None, lines)
    lines = filter(lambda x: x.startswith("#"), lines)
    return tuple(lines)

# ref: https://github.com/pypa/pip/blob/7ed5e12ae83ef90ac33be33555ea52f61457c1d2/setup.py#L19
def get_version(rel_path):
    for line in read(rel_path).splitlines():
        if line.startswith('__version__'):
            delim = '"' if '"' in line else "'"
            return line.split(delim)[1]
    else:
        raise RuntimeError("Unable to find version string.")

setup(
    name="napalm-mikrotik",
    version=get_version("napalm_mikrotik/__init__.py"),
    description="Network Automation and Programmability Abstraction Layer driver for Mikrotik Router OS using SSH",
    long_description=read('README.md'),
    long_description_content_type="text/markdown",

    license='Apache License 2.0',
    classifiers=[
        'Topic :: Utilities',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Operating System :: POSIX :: Linux',
        'Operating System :: MacOS',
    ],
    url="https://github.com/johnbarneta/napalm-mikrotik",

    author="Juan Gomez (Phicus Tecnologia S.L.)",
    author_email="jgomez@phicus.es",

    packages=find_packages(),

    include_package_data=True,
    install_requires=parse_reqs('requirements.txt'),
)
