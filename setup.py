
from distutils.core import setup
import deproxy

setup(
    name='deproxy',
    version=deproxy.__version__,
    packages=['deproxy', ],
    license='MIT License',
    long_description=open('README.rst').read(),
    author='izrik',
    author_email='izrik@yahoo.com',
    url='https://github.com/izrik/deproxy',
    description='Python library for testing HTTP proxies.',
    classifiers=(
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
    ),
)
