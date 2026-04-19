from __future__ import annotations

import config  # noqa: F401 - imported for module-level access via glob.config

__all__ = ('db', 'redis', 'http', 'version', 'cache', 'sys', 'config')

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aiohttp import ClientSession
    from cmyui.mysql import AsyncSQLPool
    from cmyui.version import Version
    from redis import asyncio as aioredis

db: AsyncSQLPool
redis: aioredis  # ty:ignore[invalid-type-form]
http: ClientSession
version: Version

cache = {
    'bcrypt': {}
}
sys = {}
