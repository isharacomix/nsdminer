from distutils.core import setup
setup(
    name='nsdminer',
    version='0.0.3',
    author='Barry Peddycord III',
    author_email='bwpeddyc@ncsu.edu',
    maintainer='Peng Ning',
    maintainer_email='pning@ncsu.edu',
    description=('Library for discovering network service dependencies from '
                 'network traffic flows.'),
    license='Copyright 2011, 2012 North Carolina State University',
    url='http://discovery.csc.ncsu.edu/',
    packages=['nsdminer'],
    data_files=[('/usr/local/bin/', ['nsdmine'])]
)
