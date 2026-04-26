from setuptools import setup, find_packages

setup(
    name="zta-guard",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        "PyYAML>=6.0",
        "requests>=2.28",
        "rich>=15.0",
    ],
    entry_points={
        "console_scripts": [
            "zta=cli.main:main"
        ]
    },
)
