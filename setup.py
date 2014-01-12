from distutils.core import setup

setup(
    name='PyBLE',
    version='0.1dev',
    author='Jessica McKellar, Adam Fletcher',
    author_email='jesstess@mit.edu, adamf@csh.rit.edu',
    packages=['ble'],
    url='https://github.com/jesstess/PyBLE',
    description='Bluetooth Low Energy interface.',
    long_description=open('README.md').read(),
    install_requires=["bluez"]
)
