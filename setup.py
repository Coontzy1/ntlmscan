# paths.dict is installed alongside the module so pipx/installed users find it
from setuptools import setup

setup(data_files=[("ntlmscan", ["paths.dict"])])
