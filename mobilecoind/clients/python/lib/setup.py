#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="mobilecoin",
    version="0.3.3",
    author="MobileCoin",
    author_email="support@mobilecoin.com",
    description="Python bindings for the MobileCoin daemon API.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/mobilecoinfoundation/mobilecoin/tree/master/mobilecoind/clients/python/lib",
    package_data={"mobilecoin": ["py.typed"]},
    packages=["mobilecoin"],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
    test_suite="nose.collector",
    tests_require=["nose"],
    install_requires=["grpcio", "grpcio-tools"],
)
