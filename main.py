#!/usr/bin/env python3.11
# -*- coding: utf-8 -*-

__all__ = ()

import os
import asyncio
import threading
from datetime import datetime, timezone

import aiohttp
from redis import asyncio as aioredis
import orjson
from quart import Quart, g
from quart import render_template

from objects import glob
from objects import utils

from cmyui.logging import Ansi
from cmyui.logging import log
from objects.utils import klogging
from cmyui.mysql import AsyncSQLPool
from cmyui.version import Version
import logging, time
import json
from quart import Response, request

app = Quart(f'{glob.config.app_name}')

# Auto-reload templates in dev so .html changes appear without container restart.
# In production (QUART_ENV != 'development'), templates stay cached for performance.
if os.environ.get('QUART_ENV') == 'development':
    app.config['TEMPLATES_AUTO_RELOAD'] = True

version = Version(2, 0, 0)

# used to secure session data.
# we recommend using a long randomly generated ascii string.
app.secret_key = glob.config.secret_key

utils.klogging.configure_logging()

print(f"App Name: {app.name}")

@app.before_serving
async def mysql_conn() -> None:
    glob.db = AsyncSQLPool()
    await glob.db.connect(glob.config.mysql) # type: ignore
    klogging.log('Connected to MySQL!', Ansi.LGREEN)

@app.before_serving
async def http_conn() -> None:
    glob.http = aiohttp.ClientSession(json_serialize=lambda x: orjson.dumps(x).decode())
    klogging.log('Got our Client Session!', Ansi.LGREEN)

@app.before_serving
async def redis_conn() -> None:
    glob.redis = aioredis
    glob.redis = await aioredis.from_url(glob.config.REDIS_DSN)
    klogging.log('Connected to Redis!', Ansi.LGREEN)


@app.before_serving
async def run_bg_tasks() -> None:
    # Schedule the execution of the set_sys_data function
    asyncio.create_task(set_sys_data())

async def set_sys_data(silent=False) -> None:
    i = 0
    l = 0
    if silent:
        sys_data = await glob.db.fetchall('SELECT * FROM server_data')
        sys_data_dict = {item['type']: item['value'] for item in sys_data}
        glob.sys = sys_data_dict
    else:
        while i < 3:
            i += 1
            sys_data = await glob.db.fetchall('SELECT * FROM server_data')
            sys_data_dict = {item['type']: item['value'] for item in sys_data}
            glob.sys = sys_data_dict
            if i == 1:
                klogging.log('Set Server Data From DB', klogging.Ansi.LGREEN)
            if i == 2:
                klogging.log('Updated Server Data From DB', klogging.Ansi.LGREEN, logger='root') # Using root logger to log to console only
                i = 1
            await asyncio.sleep(30)

@app.before_request
async def start_timer():
    g.start_time = time.time()

# log all responses
@app.after_request
async def after_request(response: Response) -> Response:
    await klogging.access_log(request, response)
    return response

@app.after_serving
async def shutdown() -> None:
    await glob.db.close()
    await glob.http.close()    

# globals which can be used in template code

# Dynamic cache buster — appends ?v={mtime_hex} to static file paths.
# mtime changes only when the file changes, so browsers cache forever
# but instantly pick up new versions on deploy.
_static_root = os.path.join(os.path.dirname(__file__), 'static')
_bust_cache: dict[str, str] = {}

@app.template_global()
def bust(path: str) -> str:
    """Return path with ?v=<mtime_hex> for cache busting.
    Usage in templates: {{ bust('/static/css/main.css') }}
    """
    cached = _bust_cache.get(path)
    if cached and not app.debug:
        return cached

    file_path = path.replace('/static/', '', 1)
    full_path = os.path.join(_static_root, file_path)
    try:
        mtime = int(os.path.getmtime(full_path))
        result = f"{path}?v={mtime:x}"
    except OSError:
        result = path

    _bust_cache[path] = result
    return result

@app.template_global()
def appVersion() -> str:
    return repr(version)

@app.template_global()
def appName() -> str:
    return glob.config.app_name

@app.template_global()
def captchaKey() -> str:
    return glob.config.hCaptcha_sitekey

@app.template_global()
def domain() -> str:
    return glob.config.domain

@app.template_global()
def developerMode() -> bool:
    return glob.config.developer_mode

@app.template_global()
def now() -> 'datetime':
    return datetime.now(timezone.utc)

@app.before_request
async def inject_globals():
    """App-wide defaults for g — ensures all blueprints have these set."""
    g.globalNotice = None
    g.isDevEnv = False
    g.maintenance = False

    try:
        if glob.sys.get('globalNotice'):
            g.globalNotice = glob.sys['globalNotice']
        if glob.sys.get('isDevEnv') == "True":
            g.isDevEnv = True
        if glob.sys.get('maintenance') == "True":
            g.maintenance = True
    except Exception as e:
        import logging as _logging
        _logging.getLogger(__name__).warning(f"inject_globals error: {e}")

from blueprints.frontend import frontend
app.register_blueprint(frontend)

from blueprints.hinaDir import hina_friends
app.register_blueprint(hina_friends)

from blueprints.admin import admin
app.register_blueprint(admin, url_prefix='/admin')

from blueprints.hinaDir import hina_admin
app.register_blueprint(hina_admin, url_prefix='/admin-v2')

from blueprints.hinaDir import hina_beatmaps
app.register_blueprint(hina_beatmaps)

from blueprints.hinaDir import hina_team
app.register_blueprint(hina_team)

from blueprints.hinaDir import hina_pp_records
app.register_blueprint(hina_pp_records)

from blueprints.hinaDir import hina_auth
app.register_blueprint(hina_auth)

@app.errorhandler(404)
async def page_not_found(e):
    # NOTE: we set the 404 status explicitly
    return (await render_template('404.html'), 404)

if __name__ == '__main__':
    os.chdir(os.path.dirname(os.path.realpath(__file__)))
    app.run(port=glob.config.app_port, debug=glob.config.debug) # blocking call
