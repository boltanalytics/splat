from setuptools import setup

setup(
    name="splat",
    version="0.1",
    packages=["splat"],
    include_package_data=True,
    url="https://github.com/boltanalytics/splat",
    license="",
    author="Bolt Analytics",
    author_email="support@boltanalytics.com",
    description="Estimate compression of Splunk logs",
    install_requires=[
        "click>=7.1.2",
        "numpy>=1.19.4",
        "pandas>=1.1.4",
        "python-dateutil>=2.8.1",
        "pytz>=2020.4",
        "six>=1.15.0",
        "splunk-sdk>=1.6.14"
    ],
    entry_points='''
        [console_scripts]
        splat=splat.splat:main
    ''',
    zip_safe=False
)
