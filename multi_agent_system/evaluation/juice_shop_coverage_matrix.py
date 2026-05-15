"""Backward-compat shim. Module renamed to coverage_matrix."""
import warnings
warnings.warn(
    "juice_shop_coverage_matrix is deprecated, use coverage_matrix",
    DeprecationWarning, stacklevel=2,
)
from .coverage_matrix import *   # noqa: F401,F403
try:
    from .coverage_matrix import main   # noqa: F401
except ImportError:
    pass
