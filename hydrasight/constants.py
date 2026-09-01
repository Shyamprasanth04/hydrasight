"""Single-sourced package metadata constants.

These are defined here (rather than in :mod:`hydrasight.__init__`) so that
configuration code can import them without triggering a package-import
cycle.  ``hydrasight/__init__.py`` re-exports the same names and exposes
the dunder attributes (``__version__`` etc.) used by packaging tooling.
"""

from __future__ import annotations

__version__ = "4.1.0"
__codename__ = "OBSIDIAN"
__app_name__ = "HydraSight"
__title__ = "HydraSight"
__license__ = "MIT"
__author__ = "Shyam Prasanth"
__summary__ = (
    "AI-assisted, authorization-gated offensive-security orchestration "
    "framework for authorized environments"
)

VERSION = __version__
CODENAME = __codename__
APP_NAME = __app_name__

__all__ = [
    "__version__",
    "__codename__",
    "__app_name__",
    "__title__",
    "__license__",
    "__author__",
    "__summary__",
    "VERSION",
    "CODENAME",
    "APP_NAME",
]
