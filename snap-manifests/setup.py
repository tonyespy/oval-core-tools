from setuptools import setup

setup(
    name='snap-manifests',
    version='0.1',
    url='https://github.com/mypackage.git',
    author='Eduardo Barretto',
    author_email='eduardo.barretto@canonical.com',
    description='A tool to generate OCI OVAL manifests for an Ubuntu Core system',
    scripts=["snap_manifest.py"],
)
