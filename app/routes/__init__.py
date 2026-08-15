"""URL route blueprints."""

from .main import bp as main_bp
from .tools import bp as tools_bp

__all__ = ["main_bp", "tools_bp"]