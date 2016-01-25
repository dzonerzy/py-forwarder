import os
from setuptools import setup


# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


setup(
        name="py-forwarder",
        version="0.0.1",
        author="Daniele Lingualossa",
        author_email="danielelinguaglossa@gmail.com",
        description="Simple and trivial port forwarder written in python",
        license="BSD",
        keywords="",
        url="https://github.com/dzonerzy/py-forwarder",
        packages=['py-forwarder', 'tests'],
        classifiers=[
            "Development Status :: 3 - Alpha",
            "Topic :: Utilities"
        ],
)
