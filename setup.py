from setuptools import setup, find_packages

setup(
    name="Tusk",
    version="0.1",
    description="Lightweight vulnerability scanner",
    python_requires=">=3.11",

    py_modules=["cli"],
    packages=find_packages(),

    install_requires=[
        "requests",
        "rich",
        "pyyaml"
    ],

    entry_points={
        "console_scripts": [
            "tusk=cli:main"
        ]
    }
)
