from setuptools import setup, find_packages

setup(
    name='passiverecon',
    version='1.0.0',
    description='Comprehensive Passive Security Scanner',
    author='PassiveRecon Team',
    packages=find_packages(),
    install_requires=[
        'requests>=2.28.0',
        'urllib3>=1.26.0',
        'beautifulsoup4>=4.11.0',
        'dnspython>=2.3.0',
        'jinja2>=3.1.0',
        'colorama>=0.4.6',
        'tldextract>=3.4.0',
        'cryptography>=38.0.0',
    ],
    entry_points={
        'console_scripts': [
            'passiverecon=passiverecon:main',
        ],
    },
    python_requires='>=3.7',
)
