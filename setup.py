#!/usr/bin/env python

from distutils.core import setup
"""
def get_requirements(file_name):
  f = open(file_name,'r')
  for line in f.read.split('\n'):
    if len(line) > 0 and "#" not in line[0]:
      pass
"""
    
setup(name='caslib',
      version='2.0.0',
      description='CAS Client library',
      author='Steven Gregory',
      author_email='sgregory@iplantcollaborative.org',
      url='https://github.com/iPlantCollaborativeOpenSource/caslib.py',
      py_modules=['caslib'],
      install_requires = ['requests == 2.2.0'],
     )
