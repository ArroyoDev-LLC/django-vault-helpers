#!/usr/bin/env python
from setuptools import setup, find_packages, Distribution
import codecs
import os.path

# Make sure versiontag exists before going any further
Distribution().fetch_build_eggs('versiontag>=1.2.0')

from versiontag import get_version, cache_git_tag  # NOQA


packages = find_packages('src')

install_requires = [
    '12factor-vault>=0.1.15',
    'Django>=1.9.6,<2.0',
    'portalocker>=1.1.0',
    'pytz>=2017.2',
    'python-dateutil>=2.6.1'
]

extras_require = {
    'aws': [
        'boto3>=1.4.7',
        'botocore>=1.7.22',
    ],
    'database': [
        'dj-database-url>=0.4.2',
        'django-postgresql-setrole>=1.0.10',
    ],
    'development': [
        'flake8>=3.3.0',
        'psycopg2>=2.7.1',
        'tox>=2.7.0',
        'versiontag>=1.2.0',
    ],
}



def fpath(name):
    return os.path.join(os.path.dirname(__file__), name)


def read(fname):
    return codecs.open(fpath(fname), encoding='utf-8').read()


cache_git_tag()

setup(
    name='django-vault-helpers',
    description="Helper functionality for obtaining secrets and credentials from Hashicorp Vault in a Django project",
    version=get_version(pypi=True),
    long_description=open('README.rst').read(),
    classifiers=[
        'Development Status :: 1 - Planning',
        'Environment :: Console',
        'Environment :: Web Environment',
        'Framework :: Django',
        'Framework :: Django :: 1.9',
        'Framework :: Django :: 1.10',
        'Framework :: Django :: 1.11',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: ISC License (ISCL)',
        'Operating System :: Unix',
        'Operating System :: MacOS :: MacOS X',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],
    author='Craig Weber',
    author_email='crgwbr@gmail.com',
    url='https://gitlab.com/thelabnyc/django-vault-helpers',
    license='ISC',
    package_dir={'': 'src'},
    packages=packages,
    include_package_data=True,
    install_requires=install_requires,
    extras_require=extras_require,
)
