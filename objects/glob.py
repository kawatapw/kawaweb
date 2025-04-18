# -*- coding: utf-8 -*-

__all__ = ("db", "redis", "http", "version", "cache", "sys")

from typing import TYPE_CHECKING
import config  # imported for indirect use

if TYPE_CHECKING:
    from aiohttp import ClientSession
    from cmyui.mysql import AsyncSQLPool
    from redis import asyncio as aioredis
    from cmyui.version import Version

db: "AsyncSQLPool"
redis: "aioredis"
http: "ClientSession"
version: "Version"

cache = {"bcrypt": {}}
sys = {}
