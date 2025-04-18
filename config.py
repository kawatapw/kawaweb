# -*- coding: utf-8 -*-
from __future__ import annotations

import os
from datetime import date

from dotenv import load_dotenv

load_dotenv()


def read_list(value: str) -> list[str]:
    return [v.strip() for v in value.split(",")]


# app info
app_name = os.environ["APP_NAME"]
app_port = int(os.environ["APP_PORT"])

# secret key
secret_key = os.environ["SECRET_KEY"]
# API Key for Admin Requests
api_key = os.environ["API_KEY"]

# hCaptcha settings:
hCaptcha_sitekey = os.environ["HCAPTCHA_SITEKEY"]
hCaptcha_secret = os.environ["HCAPTCHA_SECRET"]

# domain (used for api, avatar, etc)
domain = os.environ["DOMAIN"]
# official domain (Used for the official domain of the server when in Dev Mode)
official_domain = os.environ["OFFICIAL_DOMAIN"]

# max image size for avatars, in megabytes
max_image_size = int(os.environ["MAX_IMAGE_SIZE"])
max_image_size_supporter = int(os.environ["MAX_IMAGE_SIZE_SUPPORTER"])

# mysql credentials
mysql = {
    "db": os.environ["MYSQL_DB"],
    "host": os.environ["MYSQL_HOST"],
    "user": os.environ["MYSQL_USER"],
    "password": os.environ["MYSQL_PASSWORD"],
}

REDIS_HOST = os.environ["REDIS_HOST"]
REDIS_PORT = int(os.environ["REDIS_PORT"])
REDIS_USER = os.environ["REDIS_USER"]
REDIS_PASS = os.environ["REDIS_PASS"]
REDIS_DB = int(os.environ["REDIS_DB"])

REDIS_AUTH_STRING = f"{REDIS_USER}:{REDIS_PASS}@" if REDIS_USER and REDIS_PASS else ""
REDIS_DSN = f"redis://{REDIS_AUTH_STRING}{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}"

# path to gulag root (must have leading and following slash)
path_to_gulag = os.environ["PATH_TO_GULAG"]
seperate_data_path = os.environ["SEPERATE_DATA_PATH"]

# enable debug (disable when in production to improve performance)
debug = os.environ["DEBUG"]

# Logging settings
LOG_WITH_COLORS = os.environ["LOG_WITH_COLORS"]
SERVICE_NAME = os.getenv(
    "SERVICE_NAME", "kawata"
)  # Brand Name of the Service, eg. "Kawata, Akatsuki, etc."
CONTAINER_NAME = os.getenv(
    "CONTAINER_NAME", "web"
)  # Name of Container, eg. "kawaweb, web, etc."

# disallowed names (hardcoded banned usernames)
disallowed_names = read_list(os.environ["DISALLOWED_NAMES"])

# disallowed passwords (hardcoded banned passwords)
disallowed_passwords = read_list(os.environ["DISALLOWED_PASSWORDS"])

# enable registration
registration = os.environ["ENABLE_REGISTRATION"]

# social links (used throughout guweb)
github = os.getenv("GITHUB", "https://github.com/kawatapw/kawaweb")
discord_server = os.getenv("DISCORD_SERVER", "https://discord.com/invite/")
youtube = os.getenv("YOUTUBE", "https://youtube.com/")
twitter = os.getenv("TWITTER", "https://twitter.com/")
instagram = os.getenv("INSTAGRAM", "https://instagram.com/")

RANKED_WEBHOOK_URL = os.environ["RANKED_WEBHOOK_URL"]
ADMIN_WEBHOOK_URL = os.environ["ADMIN_WEBHOOK_URL"]
