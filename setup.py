#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# vim: ai ts=4 sts=4 et sw=4
from setuptools import setup

setup(
    name="ferme-ta-gueule",
    version="0.1",
    license="MIT",
    author="Grégory Duchatelet",
    author_email="greg@easyflirt.com",
    maintainer="Easyflirt development community",
    maintainer_email="greg@easyflirt.com",
    install_requires=["elasticsearch","termcolor"],
    description="Tail de logs d'erreurs",
    packages=[],
    scripts=["ferme-ta-gueule.py"]
)
