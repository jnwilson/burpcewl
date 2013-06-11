#! /usr/bin/env python
import os
from setuptools import setup

setup(name='burpcewl',
      version='1.0',
      description='Burp session file password grabber',
      author='Joseph N. Wilson',
      author_email='jnw@cise.ufl.edu',
      license='BSD',
      url='https://github.com/jnwilson/burpcewl',
      py_modules=['burpcewl'],
      install_requires=[
          'burp2xml',
          'bs4',
          'python-magic',
       ],
      dependency_links=[
          'https://github.com/jnwilson/burp2xml/tarball/master#egg=burp2xml',
          'http://www.crummy.com/software/BeautifulSoup/bs4/download/4.2/beautifulsoup4-4.2.1.tar.gz#egg=bs4',
          'https://github.com/ahupp/python-magic/tarball/master#egg=python-magic',
        ],
      classifiers=[
          'Development Status :: 3 - Alpha',
          'License :: OSI Approved :: BSD License',
      ],
)
