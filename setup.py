from setuptools import setup, find_packages

setup(name='caslib.py',
      version='2.3.0',
      description='CAS Client library',
      author='iPlant Collaborative',
      author_email='atmodevs@gmail.com',
      url='https://github.com/iPlantCollaborativeOpenSource/caslib.py',
      py_modules=['caslib'],
      packages=find_packages(),
      install_requires = ['requests >= 2.2.1'],
     )
