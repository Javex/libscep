from setuptools import setup, find_packages, Extension
import os
import re

vfile = open(os.path.join(os.path.dirname(__file__), 'scep',
                          '__init__.py'))
VERSION = re.search(r'.*__version__ = "(.*?)"', vfile.read(), re.S).group(1)
vfile.close()

package_requires = [
]

_scep = Extension(
    'scep._scep', ['bindings/scep.c'],
    include_dirs=['../../../build'],
    library_dirs=['../../../build/src'],
    libraries=['scep'],
    extra_link_args=['-lcrypto'])

setup(
    name="scep",
    version=VERSION,
    packages=find_packages(),
    install_requires=package_requires,
    ext_modules=[_scep],
)
