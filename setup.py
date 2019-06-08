
from setuptools import setup

setup(
        name='lan_attack',
        version='0.1',
        description='Running Local Area Network Attacks Using Pympact',
        url='https://github.com/jaredwelsh/LAN-Attacks/',
        author='Jared Welsh',
        author_email='jareddwelsh@protonmail.com',
        license='Apache-2.0',
        packages=['lan_attack'],
        install_requires=[
            'pympact',
            'scapy'
            ]
        zip_safe=False
        )
