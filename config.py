"""
config.py — Root-level shim.

The real configuration lives in app/config.py. This file exists solely to
maintain backwards-compatibility for Alembic migrations, which import from
the project root.
"""
from app.config import BaseConfig, DevelopmentConfig, ProductionConfig, TestingConfig, get_config

__all__ = [
    "BaseConfig",
    "DevelopmentConfig",
    "ProductionConfig",
    "TestingConfig",
    "get_config",
]

# Legacy alias used by existing alembic env.py
Config = DevelopmentConfig
