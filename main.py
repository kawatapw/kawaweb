#!/usr/bin/env python3.11
# -*- coding: utf-8 -*-

__all__ = ()

import os
import asyncio
import threading

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

app = Quart(f"{glob.config.app_name}")

version = Version(1, 3, 0)

# used to secure session data.
# we recommend using a long randomly generated ascii string.
app.secret_key = glob.config.secret_key

utils.klogging.configure_logging()

print(f"App Name: {app.name}")


@app.before_serving
async def mysql_conn() -> None:
    glob.db = AsyncSQLPool()
    await glob.db.connect(glob.config.mysql)  # type: ignore
    klogging.log("Connected to MySQL!", Ansi.LGREEN)


@app.before_serving
async def http_conn() -> None:
    glob.http = aiohttp.ClientSession(json_serialize=lambda x: orjson.dumps(x).decode())
    klogging.log("Got our Client Session!", Ansi.LGREEN)


@app.before_serving
async def redis_conn() -> None:
    glob.redis = aioredis
    glob.redis = await aioredis.from_url(glob.config.REDIS_DSN)
    klogging.log("Connected to Redis!", Ansi.LGREEN)


@app.before_serving
async def run_bg_tasks() -> None:
    # Schedule the execution of the set_sys_data function
    asyncio.create_task(set_sys_data())


async def set_sys_data(silent=False) -> None:
    i = 0
    l = 0
    if silent:
        sys_data = await glob.db.fetchall("SELECT * FROM server_data")
        sys_data_dict = {item["type"]: item["value"] for item in sys_data}
        glob.sys = sys_data_dict
    else:
        while i < 3:
            i += 1
            sys_data = await glob.db.fetchall("SELECT * FROM server_data")
            sys_data_dict = {item["type"]: item["value"] for item in sys_data}
            glob.sys = sys_data_dict
            if i == 1:
                klogging.log("Set Server Data From DB", klogging.Ansi.LGREEN)
            if i == 2:
                klogging.log(
                    "Updated Server Data From DB", klogging.Ansi.LGREEN, logger="root"
                )  # Using root logger to log to console only
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


from blueprints.frontend import frontend

app.register_blueprint(frontend)

from blueprints.admin import admin

app.register_blueprint(admin, url_prefix="/admin")


@app.errorhandler(404)
async def page_not_found(e):
    # NOTE: we set the 404 status explicitly
    return (await render_template("404.html"), 404)


if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.realpath(__file__)))
    app.run(port=glob.config.app_port, debug=glob.config.debug)  # blocking call
