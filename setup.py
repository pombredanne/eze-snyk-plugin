#!/usr/bin/env python

import re
from os import path
from pathlib import Path

from setuptools import find_packages, setup


def read_version() -> str:
    """Reads version from eze/__init__.py"""
    data_folder = Path(path.dirname(__file__))
    file_path = data_folder / "src" / "__init__.py"
    with open(file_path, encoding="utf-8") as file:
        content = file.read()
    return re.search(r"__version__ = \"([^']+)\"", content).group(1)


setup(
    version=read_version(),
    packages=find_packages(exclude=["tests.*", "tests"]),
    # INFO: setup.py Entry point setup
    # https://setuptools.readthedocs.io/en/latest/userguide/entry_point.html
    # entry_points={"eze.plugins": "example=src.tools"},
)
