#!/usr/bin/env python


from setuptools import setup

setup(name='aws_stack_diff',
      version='0.1',
      description='A tool to check the difference between a stack and its resources',
      classifiers=[
          'Development Status :: 3 - Alpha',
          'Environment :: Console',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: MIT License',
          'Natural Language :: English',
          'Programming Language :: Python :: 2.7',
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 3.0',
          'Programming Language :: Python :: 3.1',
          'Programming Language :: Python :: 3.2',
          'Programming Language :: Python :: 3.3',
          'Programming Language :: Python :: 3.4',
          'Programming Language :: Python :: 3.5',
          'Programming Language :: Python :: 3.6',
          'Topic :: Software Development :: Libraries',
      ],
      url='https://github.com/fivestars/aws_cloudstack_diff_tool',
      author='Fivestars',
      license='MIT',
      packages=['aws_cloudstack_diff_tool'],
      install_requires=[
          'git+ssh://git@github.com/fivestars/boto3_wrapper.git@master',
          'datadiff==2.0.0',
          'six==1.10.0',
      ],
      include_package_data=True,
      zip_safe=True)
