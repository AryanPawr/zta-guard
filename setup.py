from setuptools import setup, find_packages

setup(
    name="zta-guard",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        "rich",
        "requests"
    ],
    entry_points={
        "console_scripts": [
            "zta=cli.main:main"
        ]
    },
)