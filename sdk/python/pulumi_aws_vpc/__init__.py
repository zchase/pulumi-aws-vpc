# coding=utf-8
# *** WARNING: this file was generated by Pulumi SDK Generator. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

from . import _utilities
import typing
# Export this package's modules as members:
from ._enums import *
from .provider import *
from .vpc import *
from ._inputs import *
_utilities.register(
    resource_modules="""
[
 {
  "pkg": "aws-vpc",
  "mod": "index",
  "fqn": "pulumi_aws_vpc",
  "classes": {
   "aws-vpc:index:Vpc": "Vpc"
  }
 }
]
""",
    resource_packages="""
[
 {
  "pkg": "aws-vpc",
  "token": "pulumi:providers:aws-vpc",
  "fqn": "pulumi_aws_vpc",
  "class": "Provider"
 }
]
"""
)