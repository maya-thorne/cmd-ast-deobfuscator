"""
Bridge module exposing IOCTransformPass within the transforms package.
"""

from ..ioc.transforms import IOCTransformPass, extract_iocs

__all__ = [
    "IOCTransformPass",
    "extract_iocs",
]
