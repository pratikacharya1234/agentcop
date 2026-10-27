"""Stub (tests first). Logic arrives in the build step."""
from .detective import Result, investigate
from .provider import TemplateProvider
from .schema import Severity

__all__ = ["Result", "Severity", "TemplateProvider", "investigate"]
