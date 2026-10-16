"""
Package interface for I/O Redirection and Stream Routing engine.
"""

from .models import (
    StreamType,
    RedirectOperator,
    DestinationType,
    RedirectEntry,
    StreamRoute,
    RedirectPlan,
    RedirectMetrics
)
from .extractor import (
    is_device_destination,
    classify_destination,
    extract_redirections,
    build_redirect_tree
)
from .router import (
    StreamRouter,
    MAX_FORWARD_DEPTH
)

__all__ = [
    'StreamType',
    'RedirectOperator',
    'DestinationType',
    'RedirectEntry',
    'StreamRoute',
    'RedirectPlan',
    'RedirectMetrics',
    'is_device_destination',
    'classify_destination',
    'extract_redirections',
    'build_redirect_tree',
    'StreamRouter',
    'MAX_FORWARD_DEPTH'
]
