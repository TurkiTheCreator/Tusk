from setuptools import setup, find_packages


setup(
    name="Tusk",
    version="0.1",
    description="Lightweight vulnerability scanner",

    packages=find_packages(),

    install_requires=[
        "requests"
    ],

    entry_points={
        "console_scripts": [
            "Tusk=main:main"
        ]
    }
)