"""P2 target adapters for stack-specific lifecycle conventions."""

from .base import TargetAdapter
from .registry import adapter_for

__all__ = ["TargetAdapter", "adapter_for"]
