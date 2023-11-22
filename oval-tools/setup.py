from setuptools import setup

setup(
    name='oval-tools',
    version='0.1',
    url='https://github.com/mypackage.git',
    author='Eduardo Barretto, Tony Espy',
    author_email='eduardo.barretto@canonical.com, espy@canonical.com',
    description='Tools for OCI OVAL scaning for Ubuntu Core',
    scripts=["snap_manifest.py", "parse_oval_results.py"],
)
