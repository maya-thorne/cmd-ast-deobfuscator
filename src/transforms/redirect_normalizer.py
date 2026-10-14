"""
Backward compatibility bridge for redirect normalizer pass.
"""

from .redirection_pass import RedirectionPass, RedirectNormalizerPass

__all__ = ['RedirectionPass', 'RedirectNormalizerPass']
