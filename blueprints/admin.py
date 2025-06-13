# -*- coding: utf-8 -*-
__all__ = ()

import datetime
import hashlib
import requests
from operator import is_
from typing import Literal, List, Union, Callable
import bcrypt

import timeago
from quart import Blueprint, jsonify, request, render_template, session
from discord_webhook import DiscordWebhook, DiscordEmbed
import json

from constants import regexes
from objects import glob
from objects.utils import flash, get_safe_name, klogging, error_catcher
from objects.privileges import Privileges, ComparePrivs, GetPriv

from blueprints import frontend


admin = Blueprint("admin", __name__)


class User:
    def __init__(self, id):
        self.id = id

    @error_catcher
    async def fetchUser(self):
        data = await glob.db.fetch(f"SELECT * FROM users WHERE id = {self.id}")
        if data is None:
            raise ValueError(f"User {self.id} does not exist.")

        self.name = data["name"]
        self.safe_name = data["safe_name"]
        self.email = data["email"]
        self.priv = data["priv"]
        self.country = data["country"]
        self.silence_end = data["silence_end"]
        self.donor_end = data["donor_end"]
        self.creation_time = data["creation_time"]
        self.latest_activity = data["latest_activity"]
        self.clan_id = data["clan_id"]
        self.clan_priv = data["clan_priv"]
        self.preferred_mode = data["preferred_mode"]
        self.play_style = data["play_style"]
        self.custom_badge_name = data["custom_badge_name"]
        self.custom_badge_icon = data["custom_badge_icon"]
        self.userpage_content = data["userpage_content"]


class Map:
    def __init__(self, id):
        self.id = id

    @error_catcher
    async def fetchMap(self):
        data = await glob.db.fetch(f"SELECT * FROM maps WHERE id = {self.id}")
        if data is None:
            raise ValueError(f"Map {self.id} does not exist.")

        self.set_id = data["set_id"]
        self.status = data["status"]
        self.md5 = data["md5"]
        self.artist = data["artist"]
        self.title = data["title"]
        self.version = data["version"]
        self.creator = data["creator"]
        self.last_update = data["last_update"]
        self.total_length = data["total_length"]
        self.max_combo = data["max_combo"]
        self.frozen = data["frozen"]
        self.plays = data["plays"]
        self.passes = data["passes"]
        self.mode = data["mode"]
        self.bpm = data["bpm"]
        self.cs = data["cs"]
        self.ar = data["ar"]
        self.od = data["od"]
        self.hp = data["hp"]
        self.diff = data["diff"]


class Action:
    @staticmethod
    def genID():
        time = str(int(datetime.datetime.now().timestamp()))
        actionmd5 = hashlib.md5(time.encode()).hexdigest().encode()
        actionbcrypt = bcrypt.hashpw(actionmd5, bcrypt.gensalt())
        return actionbcrypt[29:].decode("utf-8")

    def __init__(self, type, targets):
        self.id = Action.genID()
        self.mod = session["user_data"]["id"]
        self.targets = targets
        self.type: Literal[
            "wipe",
            "restrict",
            "unrestrict",
            "silence",
            "unsilence",
            "changepassword",
            "changeprivileges",
            "editmap",
            "editaccount",
            "addbadge",
            "removebadge",
            "removescore",
        ] = type
        function_map = {
            "wipe": wipe,
            "restrict": restrict,
            "unrestrict": unrestrict,
            "silence": silence,
            "unsilence": unsilence,
            "changepassword": changepassword,
            "changeprivileges": changeprivileges,
            "editmap": editmap,
            "editaccount": editaccount,
            "addbadge": addbadge,
            "removebadge": removebadge,
            "removescore": removescore,
        }
        self.function = function_map.get(self.type)
        if self.function is None:
            raise ValueError(f"Invalid action type: {self.type}")

    async def initialize(self):
        self.mod = User(self.mod)
        await self.mod.fetchUser()
        if self.type == "editmap":
            new = []
            for m in self.targets:
                newmap = Map(m) if isinstance(m, int) else Map(int(m))
                await newmap.fetchMap()
                new.append(newmap)

            self.targets = new  # Ensure targets is a list of Map objects

        elif self.type == "removescore":
            pass

        elif self.type in ["addbadge", "removebadge"]:
            pass

        else:
            self.targets = (
                User(self.targets)
                if isinstance(self.targets, int)
                else User(int(self.targets))
            )
            await self.targets.fetchUser()

    @classmethod
    async def create(cls, type, targets):
        instance = cls(type, targets)

        await instance.initialize()

        return instance


async def wipe(action: Action, req):
    try:
        if Privileges.WipeUsers not in GetPriv(action.mod.priv):
            return jsonify(
                {
                    "status": "error",
                    "message": "You do not have permission to wipe users.",
                }
            ), 403
        modes = [0, 1, 2, 3, 4, 5, 6, 7, 8]
        await glob.db.execute(
            f"""
            INSERT INTO wiped_scores (id, map_md5, score, pp, acc, max_combo, mods, n300, n100, n50, nmiss, ngeki, nkatu, grade, status, mode, play_time, time_elapsed, client_flags, userid, perfect, online_checksum, r_replay_id)
            SELECT id, map_md5, score, pp, acc, max_combo, mods, n300, n100, n50, nmiss, ngeki, nkatu, grade, status, mode, play_time, time_elapsed, client_flags, userid, perfect, online_checksum, r_replay_id
            FROM scores
            WHERE userid = {action.targets.id};
            """
        )
        # Delete scores from scores table
        await glob.db.execute(
            f"""
            DELETE FROM scores
            WHERE userid = {action.targets.id};
            """
        )
        # Reset Players Stats
        for mode in modes:
            query = f"""
            UPDATE stats
            SET tscore = 0, rscore = 0, pp = 0, plays = 0, playtime = 0, acc = 0.000, max_combo = 0, total_hits = 0, replay_views = 0, xh_count = 0, x_count = 0, sh_count = 0, s_count = 0, a_count = 0
            WHERE id = {action.targets.id} AND mode = '{mode}';
            """
            await glob.db.execute(query)
            await glob.redis.zrem(
                f"bancho:leaderboard:{mode}",
                action.targets.id,
            )
            await glob.redis.zrem(
                f"bancho:leaderboard:{mode}:{action.targets.country}",
                action.targets.id,
            )
        await log(action)

        return jsonify(
            {
                "status": "success",
                "message": f"Successfully wiped {action.targets.name} ({action.targets.id}).",
            }
        ), 200

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


async def restrict(action: Action, req):
    try:
        if Privileges.RestrictUsers not in GetPriv(action.mod.priv):
            return jsonify(
                {
                    "status": "error",
                    "message": "You do not have permission to restrict users.",
                }
            ), 403
        if action.targets.priv == 0:
            return jsonify(
                {"status": "error", "message": "user is already restricted."}
            ), 400
        await glob.db.execute(
            f"""
            UPDATE users
            SET priv = 0
            WHERE id = {action.targets.id};
            """
        )
        await log(action)
        return jsonify(
            {
                "status": "success",
                "message": f"Successfully restricted {action.targets.name} ({action.targets.id}).",
            }
        ), 200

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


async def unrestrict(action: Action, req):
    try:
        if Privileges.RestrictUsers not in GetPriv(action.mod.priv):
            return jsonify(
                {
                    "status": "error",
                    "message": "You do not have permission to unrestrict users.",
                }
            ), 403

        if action.targets.priv != 0:
            return jsonify(
                {"status": "error", "message": "user is not already restricted."}
            ), 400

        await glob.db.execute(
            f"""
                UPDATE users
                SET priv = 1
                WHERE id = {action.targets.id};
                """
        )

        await log(action)
        return jsonify(
            {
                "status": "success",
                "message": f"Successfully unrestricted {action.targets.name} ({action.targets.id}).",
            }
        ), 200

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


async def silence(action: Action, req):
    form = await req.form
    if form.get("duration") is None:
        return jsonify({"status": "error", "message": "No duration specified."}), 400
    duration = form.get("duration")

    try:
        if Privileges.SilenceUsers not in GetPriv(action.mod.priv):
            return jsonify(
                {
                    "status": "error",
                    "message": "You do not have permission to silence users.",
                }
            ), 403

        if action.targets.silence_end != 0:
            return jsonify(
                {"status": "error", "message": "user is already silenced."}
            ), 400

        await glob.db.execute(
            f"""
                UPDATE users
                SET silence_end = {int(datetime.datetime.now().timestamp()) + int(duration) * 3600}
                WHERE id = {action.targets.id};
                """
        )

        await log(action)

        return jsonify(
            {
                "status": "success",
                "message": f"Successfully silenced {action.targets.name} ({action.targets.id}).",
            }
        ), 200

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


async def unsilence(action: Action, req):
    try:
        if Privileges.SilenceUsers not in GetPriv(action.mod.priv):
            return jsonify(
                {
                    "status": "error",
                    "message": "You do not have permission to unsilence users.",
                }
            ), 403

        if action.targets.silence_end == 0:
            return jsonify(
                {"status": "error", "message": "user is not already silenced."}
            ), 400

        await glob.db.execute(
            f"""
                UPDATE users
                SET silence_end = 0
                WHERE id = {action.targets.id};
                """
        )

        await log(action)

        return jsonify(
            {
                "status": "success",
                "message": f"Successfully unsilenced {action.targets.name} ({action.targets.id}).",
            }
        ), 200

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


async def changepassword(action: Action, req):
    form = await req.form
    try:
        if Privileges.ManageUsers not in GetPriv(action.mod.priv):
            return jsonify(
                {
                    "status": "error",
                    "message": "You do not have permission to change the password of users.",
                }
            ), 403
        if not form.get("password"):
            return jsonify({"status": "error", "message": "No password provided."}), 400
        password = form.get("password")
        if not 8 < len(password) <= 32:
            return jsonify(
                {
                    "status": "error",
                    "message": "Password must be between 8 and 32 characters.",
                }
            ), 400

        bcrypt_cache = glob.cache["bcrypt"]
        pw_bcrypt = (
            await glob.db.fetch(
                "SELECT pw_bcrypt " "FROM users " "WHERE id = %s", [action.targets.id]
            )
        )["pw_bcrypt"].encode()

        if pw_bcrypt in bcrypt_cache:
            del bcrypt_cache[pw_bcrypt]

        # calculate new md5 & bcrypt pw
        pw_md5 = hashlib.md5(password.encode()).hexdigest().encode()
        pw_bcrypt = bcrypt.hashpw(pw_md5, bcrypt.gensalt())

        # update password in cache and db
        bcrypt_cache[pw_bcrypt] = pw_md5
        await glob.db.execute(
            "UPDATE users " "SET pw_bcrypt = %s " "WHERE safe_name = %s",
            [pw_bcrypt, action.targets.safe_name],
        )

        await log(action)
        return jsonify(
            {
                "status": "success",
                "message": f"Successfully changed the password of {action.targets.name} ({action.targets.id}).",
            }
        ), 200

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


async def changeprivileges(action: Action, req):
    form = await req.form
    try:
        if not form.get("priv"):
            return jsonify(
                {"status": "error", "message": "No privileges provided."}
            ), 400
        priv = form.get("priv")

        if Privileges.ManagePrivs not in GetPriv(action.mod.priv):
            return jsonify(
                {
                    "status": "error",
                    "message": "You do not have permission to change the privileges of users.",
                }
            ), 403

        if ComparePrivs(action.targets.priv, priv):
            return jsonify(
                {
                    "status": "error",
                    "message": f"privileges are already set to {action.targets.priv}.",
                }
            ), 400

        if ComparePrivs(priv, action.mod.priv):
            return jsonify(
                {
                    "status": "error",
                    "message": "You cannot grant privileges that you don't possess.",
                }
            ), 403
        if ComparePrivs(action.mod.priv, action.targets.priv):
            return jsonify(
                {
                    "status": "error",
                    "message": "You cannot modify people with privileges that you don't possess.",
                }
            ), 403

        await glob.db.execute(
            f"""
                UPDATE users
                SET priv = {priv}
                WHERE id = {action.targets.id};
                """
        )

        await log(action)

        return jsonify(
            {
                "status": "success",
                "message": f"Successfully modified the privileges of {action.targets.name} ({action.targets.id}).",
            }
        ), 200

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


async def editmap(action: Action, req):
    form = await req.form
    data = form.get("data")
    j = json.loads(data)
    print(j)


async def editaccount(action: Action, req):
    form = await req.form
    required_fields = ["username", "email", "country", "userpage_content"]
    missing_fields = [field for field in required_fields if form.get(field) is None]

    if missing_fields:
        return jsonify(
            {
                "status": "error",
                "message": f"Missing required fields: {', '.join(missing_fields)}. Please specify all fields in an editaccount request.",
            }
        ), 400

    username = form.get("username")
    email = form.get("email")
    country = form.get("country")
    userpage_content = form.get("userpage_content")
    try:
        if Privileges.ManageUsers not in GetPriv(action.mod.priv):
            return jsonify(
                {
                    "status": "error",
                    "message": "You do not have permission to edit users.",
                }
            ), 403

        if action.targets.name != username:
            safename = get_safe_name(username)
            try:
                # because why would we make it a unique key!? :D
                if (
                    await glob.db.fetch(
                        f"SELECT * FROM users WHERE safe_name = '{safename}'"
                    )
                    is not None
                    or await glob.db.fetch(
                        f"SELECT * FROM users WHERE name = '{username}'"
                    )
                    is not None
                ):
                    return jsonify(
                        {"status": "error", "message": "Username already taken."}
                    ), 400

                await glob.db.execute(
                    f"""
                        UPDATE users
                        SET name = '{username}', safe_name = '{safename}'
                        WHERE id = {action.targets.id};
                        """
                )

            except Exception as e:
                return jsonify({"status": "error", "message": str(e)}), 400

        if action.targets.email != email:
            try:
                if not regexes.email.match(email):
                    return jsonify(
                        {
                            "status": "error",
                            "message": "email is not a valid email address.",
                        }
                    ), 400

                if (
                    await glob.db.fetch(
                        f"SELECT email FROM users WHERE email = {email}"
                    )
                    is not None
                ):
                    # do a multiacc check here maybe?
                    return jsonify(
                        {"status": "error", "message": "email already taken."}
                    ), 400

                await glob.db.execute(
                    f"""
                        UPDATE users
                        SET 'email' = '{email}'
                        WHERE id = {action.targets.id};
                        """
                )

            except Exception as e:
                return jsonify({"status": "error", "message": str(e)}), 400

        if action.targets.country != country:
            if len(country) != 2:
                # this shouldn't even be possible anyway
                # why do we not have a country table?
                return jsonify(
                    {
                        "status": "error",
                        "message": "country is not a valid country code.",
                    }
                ), 400

            try:
                await glob.db.execute(
                    f"""
                        UPDATE users
                        SET country = '{country}'
                        WHERE id = {action.targets.id};
                        """
                )

            except Exception as e:
                return jsonify({"status": "error", "message": str(e)}), 400

        if action.targets.userpage_content != userpage_content:
            try:
                await glob.db.execute(
                    f"""
                        UPDATE users
                        SET userpage_content = {userpage_content}
                        WHERE id = {action.targets.id};
                        """
                )

            except Exception as e:
                return jsonify({"status": "error", "message": str(e)}), 400

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


async def addbadge(action: Action, req):
    form = await req.form
    if form.get("badge") is None:
        return jsonify({"status": "error", "message": "No badge specified."}), 400
    badge = form.get("badge")
    try:
        if Privileges.ManageBadges not in GetPriv(action.mod.priv):
            return jsonify(
                {
                    "status": "error",
                    "message": "You do not have permission to add badges to users.",
                }
            ), 403

        if (
            await glob.db.fetch(
                f"SELECT * FROM user_badges WHERE userid = {action.targets.id} AND badge_id = {badge}"
            )
            is not None
        ):
            return jsonify(
                {"status": "error", "message": "User already has this badge."}
            ), 400

        await glob.db.execute(
            f"""
                INSERT INTO user_badges (userid, badge_id)
                VALUES ({action.targets.id}, {badge})
                """
        )

        await log(action)

        return jsonify(
            {
                "status": "success",
                "message": f"Successfully added badge {badge} to {action.targets.name} ({action.targets.id}).",
            }
        ), 200

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


async def removebadge(action: Action, req):
    form = await req.form
    if form.get("badge") is None:
        return jsonify({"status": "error", "message": "No badge specified."}), 400
    badge = form.get("badge")
    try:
        if Privileges.ManageBadges not in GetPriv(action.mod.priv):
            return jsonify(
                {
                    "status": "error",
                    "message": "You do not have permission to remove badges from users.",
                }
            ), 403
        if (
            await glob.db.fetch(
                f"SELECT * FROM user_badges WHERE userid = {action.targets.id} AND badge_id = {badge}"
            )
            is None
        ):
            return jsonify(
                {"status": "error", "message": "User does not have this badge."}
            ), 400

        await glob.db.execute(
            f"""
                DELETE FROM user_badges
                WHERE userid = {action.targets.id} AND badge_id = {badge}
                """
        )

        await log(action)

        return jsonify(
            {
                "status": "success",
                "message": f"Successfully removed badge {badge} from {action.targets.name} ({action.targets.id}).",
            }
        ), 200

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


async def removescore(action: Action, req):
    form = await req.form
    if form.get("score") is None:
        return jsonify({"status": "error", "message": "No score specified."}), 400
    try:
        score = form.get("score")

        if await glob.db.fetch(f"SELECT * FROM scores WHERE id = {score}") is None:
            return jsonify({"status": "error", "message": "Score does not exist."}), 400

        # wiped scores
        await glob.db.execute(
            f"""
                INSERT INTO wiped_scores (id, map_md5, score, pp, acc, max_combo, mods, n300, n100, n50, nmiss, ngeki, nkatu, grade, status, mode, play_time, time_elapsed, client_flags, userid, perfect, online_checksum, r_replay_id)
                SELECT id, map_md5, score, pp, acc, max_combo, mods, n300, n100, n50, nmiss, ngeki, nkatu, grade, status, mode, play_time, time_elapsed, client_flags, userid, perfect, online_checksum, r_replay_id
                FROM scores
                WHERE id = {score};
                """
        )

        await glob.db.execute(
            f"""
                DELETE FROM scores
                WHERE id = {score}
                """
        )

        await log(action)

        return jsonify(
            {
                "status": "success",
                "message": f"Successfully removed score {score} from {action.targets.name} ({action.targets.id}).",
            }
        ), 200

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


@admin.route("/action/<t>", methods=["POST"])
async def action(
    t: Literal[
        "wipe",
        "restrict",
        "unrestrict",
        "silence",
        "unsilence",
        "changepassword",
        "changeprivileges",
        "editmap",
        "editaccount",
        "addbadge",
        "removebadge",
        "removescore",
    ],
):
    if "authenticated" not in session:
        return jsonify({"status": "error", "message": "Please login first."}), 401

    if not request.content_type == "application/x-www-form-urlencoded":
        return jsonify(
            {
                "status": "error",
                "message": "Invalid content type. use application/x-www-form-urlencoded.",
            }
        ), 400

    form = await request.form
    if not form:
        return jsonify({"status": "error", "message": "No form data provided."}), 400

    if not form.get("targets"):
        return jsonify({"status": "error", "message": "No targets provided."}), 400
    targets = form.get("targets")
    if isinstance(targets, str):
        targets = targets.split(",")  # Split by comma to create a list
    action = await Action.create(t, targets)
    return await action.function(action, request)


async def log(action):
    pass


# @error_catcher
# async def log(action: Action):
#    """
#    structure of the log table:
#    - id: the id of the log. (varchar)
#    - action: the type of action performed. (varchar)
#    - reason: the reason for the action. (varchar)
#    - mod: the id of the moderator who performed the action. (int)
#    - target: the id of the user or map the action was performed on. (int)
#    - time: the time the action was performed. (datetime)
#    - type: the type of the target. 0 for user, 1 for map. (bool)
#    """
#
#    if action.type == 0:
#        await glob.db.execute(
#            f"""
#            INSERT INTO logs (id, action, reason, `mod`, target, time, type)
#            VALUES ('{action.id}', '{action.action}', '{action.reason}', {action.mod.id}, {action.targets.id}, '{datetime.datetime.now()}', {action.type});
#            """
#        )
#        webhook = DiscordWebhook(glob.config.ADMIN_WEBHOOK_URL)
#        # don't post password changes to discord, that's just dumb
#        if action.action != "changepassword":
#            embed = DiscordEmbed(
#                title=f"{action.targets.name} was {action.text} by {action.mod.name}",
#                description=f"a {action.action} was performed.",
#                color=5126045,
#                timestamp=datetime.datetime.now(),
#            )
#        else:
#            embed = DiscordEmbed(
#                title=f"{action.targets.name} was {action.text} by {action.mod.name}",
#                description=f"a {action.text} was performed.",
#                color=5126045,
#                timestamp=datetime.datetime.now(),
#            )
#
#        embed.set_author(
#            name=f"New Action By {action.mod.name}",
#            icon_url=f"https://a.kawata.pw/{action.mod.id}",
#        )
#
#        embed.add_embed_field(
#            name="Information:",
#            value=f"Action ID: {action.id}\nAction Moderator: {action.mod.name} ({action.mod.id})\nAction User: {action.targets.name} ({action.targets.id})\nAction Type: {action.action}\n Action Reason: {action.reason}",
#            inline=False,
#        )
#
#        embed.set_footer(
#            text=f"ID: {action.id}", icon_url=f"https://a.kawata.pw/{action.targets.id}"
#        )
#
#        webhook.add_embed(embed)
#        webhook.execute()
#
#    elif action.type == 1:  # TODO: Add support for Set Ranking
#        await glob.db.execute(
#            f"""
#            INSERT INTO logs (id, action, reason, `mod`, target, time, type)
#            VALUES ('{action.id}', '{action.action}', '{action.reason}', {action.mod.id}, {action.map.id}, '{datetime.datetime.now()}', {action.type});
#            """
#        )
#
#        webhook = DiscordWebhook(glob.config.RANKED_WEBHOOK_URL)
#
#        embed = DiscordEmbed(
#            title=f"{action.map.title} [{action.map.version}] was {action.text} by {action.mod.name} ({action.mod.id})",
#            description=f"[{action.map.title} [{action.map.version}]](https://osu.ppy.sh/b/{action.map.id}) was {action.text}",
#            color=5126045,
#            timestamp=datetime.datetime.now(),
#        )
#
#        embed.set_author(
#            name=f"Diff {action.text} By {action.mod.name} ({action.mod.id})",
#            icon_url=f"https://a.kawata.pw/{action.mod.id}",
#        )
#
#        embed.add_embed_field(
#            name="Information:",
#            value=f"""
#            Ranked By: {action.mod.name} ({action.mod.id})\n
#            Map: {action.map.title} [{action.map.version}] ({action.map.id})\n
#            Map Stats: CS: {action.map.cs} AR: {action.map.ar} OD: {action.map.od} HP: {action.map.hp} NM*: {action.map.diff}\n
#            Action: {action.action}\n
#            """,
#            inline=False,
#        )
#
#        embed.set_image(
#            url=f"https://assets.ppy.sh/beatmaps/{action.map.set_id}/covers/card@2x.jpg"
#        )
#
#        embed.set_footer(
#            text=f"ID: {action.id}", icon_url=f"https://a.kawata.pw/{action.mod.id}"
#        )
#
#        webhook.add_embed(embed)
#        webhook.execute()
#
#    elif action.type == 2:
#        await glob.db.execute(
#            f"""
#            INSERT INTO logs (id, action, reason, `mod`, target, time, type)
#            VALUES ('{action.id}', '{action.action}', '{action.reason}', {action.mod.id}, {action.targets.id}, '{datetime.datetime.now()}', {action.type});
#            """
#        )
#        webhook = DiscordWebhook(glob.config.ADMIN_WEBHOOK_URL)
#        # don't post password changes to discord, that's just dumb
#        embed = DiscordEmbed(
#            title=f"{action.targets.name} was {action.text} {action.badge['name']} by {action.mod.name}",
#            description=f"",
#            color=5126045,
#            timestamp=datetime.datetime.now(),
#        )
#
#        embed.set_author(
#            name=f"New Action By {action.mod.name}",
#            icon_url=f"https://a.kawata.pw/{action.mod.id}",
#        )
#
#        embed.add_embed_field(
#            name="Information:",
#            value=f"""
#            Action Moderator: {action.mod.name} ({action.mod.id})\n
#            Action User: {action.targets.name} ({action.targets.id})\n
#            Badge: {action.badge['name']} ({action.badge['id']})\n
#            Badge Description: {action.badge['description']}\n
#            """,
#            inline=False,
#        )
#
#        embed.set_footer(
#            text=f"ID: {action.id}", icon_url=f"https://a.kawata.pw/{action.targets.id}"
#        )
#
#        webhook.add_embed(embed)
#        webhook.execute()


@admin.route("/")
@admin.route("/home")
@admin.route("/dashboard")
@error_catcher
async def home():
    """Render the homepage of guweb's admin panel."""
    if not "authenticated" in session:
        return await flash("error", "Please login first.", "login")

    if not session["user_data"]["is_staff"]:
        return await flash("error", f"You have insufficient privileges.", "home")

    # fetch data from database
    dash_data = await glob.db.fetch(
        "SELECT COUNT(id) count, "
        "(SELECT name FROM users ORDER BY id DESC LIMIT 1) lastest_user, "
        "(SELECT COUNT(id) FROM users WHERE NOT priv & 1) banned "
        "FROM users"
    )

    recent_users = await glob.db.fetchall(
        "SELECT * FROM users ORDER BY id DESC LIMIT 5"
    )
    recent_scores = await glob.db.fetchall(
        "SELECT scores.*, maps.artist, maps.title, "
        "maps.set_id, maps.creator, maps.version "
        "FROM scores JOIN maps ON scores.map_md5 = maps.md5 "
        "ORDER BY scores.id DESC LIMIT 5"
    )

    return await render_template(
        "admin/home.html",
        dashdata=dash_data,
        recentusers=recent_users,
        recentscores=recent_scores,
        datetime=datetime,
        timeago=timeago,
    )


@admin.route("/users")
@admin.route("/users/")
@admin.route("/users/<int:page>")
@error_catcher
async def users(page=None):
    """Render the homepage of guweb's admin panel."""
    if not "authenticated" in session:
        return await flash("error", "Please login first.", "login")

    if not session["user_data"]["is_staff"]:
        return await flash("error", f"You have insufficient privileges.", "home")

    # Check if update query parameter is present
    update = request.args.get("update") == "true"
    search = str(request.args.get("search") or "")
    # fetch data from database
    if page == None or page < 1:
        page = 1
    Offset = 50 * (page - 1)  # for the page system to work

    if search is not None and search != "":
        if search.isdigit():
            # search is an id
            users = await glob.db.fetchall(
                "SELECT id, name, priv, country FROM users WHERE id = %s",
                (search,),
            )
        else:
            # search is a name
            users = await glob.db.fetchall(
                "SELECT id, name, priv, country FROM users WHERE name LIKE %s",
                (f"%{search}%",),
            )
    else:
        users = await glob.db.fetchall(
            "SELECT id, name, priv, country FROM users LIMIT 50 OFFSET %s",
            (Offset,),
        )

    for user in users:
        user["customisations"] = await glob.db.fetch(
            "SELECT * FROM user_customisations WHERE userid = %s", [user["id"]]
        )
    if update:
        # Return JSON response
        return jsonify(users)

    return await render_template(
        "admin/users.html",
        users=users,
        page=page,
        search=search,
        datetime=datetime,
        timeago=timeago,
    )


@error_catcher
@admin.route("/user/<int:userid>")
async def user(userid):
    """Render the homepage of guweb's admin panel."""
    if not "authenticated" in session:
        return await flash("error", "Please login first.", "login")

    if not session["user_data"]["is_staff"]:
        return await flash("error", f"You have insufficient privileges.", "home")

    # Check if update query parameter is present
    # update = request.args.get('update') == 'true'
    user = await glob.db.fetch(
        "SELECT * FROM users WHERE id = %s",
        (userid,),
    )

    user_badges = await glob.db.fetchall(
        "SELECT badge_id FROM user_badges WHERE userid = %s",
        (userid,),
    )
    badges = []
    for user_badge in user_badges:
        badge_id = user_badge["badge_id"]

        badge = await glob.db.fetch(
            "SELECT * FROM badges WHERE id = %s",
            (badge_id,),
        )

        badge_styles = await glob.db.fetchall(
            "SELECT * FROM badge_styles WHERE badge_id = %s",
            (badge_id,),
        )

        badge = dict(badge)
        badge["styles"] = {style["type"]: style["value"] for style in badge_styles}

        badges.append(badge)

        # Sort the badges based on priority
        badges.sort(key=lambda x: x["priority"], reverse=True)

    logs = {}
    hashes = await glob.db.fetchall(
        "SELECT * FROM client_hashes WHERE userid = %s ORDER BY latest_time DESC",
        (userid,),
    )
    admin_logs = await glob.db.fetchall(
        "SELECT * FROM logs WHERE `target` = %s ORDER BY `time` DESC",
        (userid,),
    )
    for admin_log in admin_logs:
        from_user = await glob.db.fetch(
            "SELECT id, name, country, priv, safe_name FROM users WHERE id = %s",
            (admin_log["mod"],),
        )
        admin_log["mod"] = from_user
    if glob.config.debug:
        print(admin_logs)
    logs["hashes"] = hashes
    logs["admin_logs"] = admin_logs
    user["badges"] = badges
    user["logs"] = logs
    # Return JSON response
    return jsonify(user)


@admin.route("/badges")
@error_catcher
async def badges():
    """Render the homepage of guweb's admin panel."""
    if not "authenticated" in session:
        return await flash("error", "Please login first.", "login")

    if not session["user_data"]["is_staff"]:
        return await flash("error", f"You have insufficient privileges.", "home")

    # Check if JSON query parameter is present
    is_json = request.args.get("json") == "true"

    # Get all badges and sort by priority
    badges = await glob.db.fetchall("SELECT * FROM badges ORDER BY priority DESC")

    # Get badge styles for each badge
    for badge in badges:
        badge_styles = await glob.db.fetchall(
            "SELECT * FROM badge_styles WHERE badge_id = %s",
            (badge["id"],),
        )
        badge["styles"] = {style["type"]: style["value"] for style in badge_styles}

    # Return JSON response if is_json is True
    if is_json:
        return jsonify(badges)

    # Return HTML response
    return await render_template(
        "admin/badges.html", badges=badges, datetime=datetime, timeago=timeago
    )


@admin.route("/badge/<int:badgeid>")
@error_catcher
async def badge(badgeid):
    """Return information about the provided badge."""
    if not "authenticated" in session:
        return await flash("error", "Please login first.", "login")

    if not session["user_data"]["is_staff"]:
        return await flash("error", f"You have insufficient privileges.", "home")

    # Get the badge from the database
    badge = await glob.db.fetch(
        "SELECT * FROM badges WHERE id = %s",
        (badgeid,),
    )

    if not badge:
        return await flash("error", f"Badge with ID {badgeid} not found.", "home")

    # Get badge styles for the badge
    badge_styles = await glob.db.fetchall(
        "SELECT * FROM badge_styles WHERE badge_id = %s",
        (badgeid,),
    )

    badge["styles"] = badge_styles

    update = request.args.get("update") == "true"
    search = str(request.args.get("search") or "")

    # if update:

    # Return JSON response
    return jsonify(badge)


@admin.route("/badge/<int:badgeid>/update", methods=["POST"])
@error_catcher
async def update_badge(badgeid):
    """Update the provided badge."""
    if not "authenticated" in session:
        return await flash("error", "Please login first.", "login")

    if not session["user_data"]["is_staff"]:
        return await flash("error", f"You have insufficient privileges.", "home")
    if Privileges.ManageBadges not in GetPriv(session["user_data"]["priv"]):
        return jsonify(
            {
                "status": "error",
                "message": "You do not have permission to update badges.",
            }
        ), 403

    data = await request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    # Update the badge in the database
    await glob.db.execute(
        "UPDATE badges SET name = %s, description = %s, priority = %s WHERE id = %s",
        (data["name"], data["description"], data["priority"], badgeid),
    )

    # Update the badge styles in the database
    for style in data["styles"]:
        existing_style = await glob.db.fetch(
            "SELECT * FROM badge_styles WHERE badge_id = %s AND type = %s",
            (badgeid, style["type"]),
        )

        if existing_style:
            # Update the existing style
            await glob.db.execute(
                "UPDATE badge_styles SET value = %s WHERE badge_id = %s AND type = %s",
                (style["value"], badgeid, style["type"]),
            )
        else:
            # Insert a new style
            await glob.db.execute(
                "INSERT INTO badge_styles (badge_id, type, value) VALUES (%s, %s, %s)",
                (badgeid, style["type"], style["value"]),
            )

    return jsonify({"success": "Badge updated successfully"}), 200


@admin.route("/badge/create", methods=["POST"])
@error_catcher
async def create_badge():
    """Create a new badge."""
    if not "authenticated" in session:
        return await flash("error", "Please login first.", "login")

    if not session["user_data"]["is_staff"]:
        return await flash("error", f"You have insufficient privileges.", "home")

    if Privileges.ManageBadges not in GetPriv(session["user_data"]["priv"]):
        return jsonify(
            {
                "status": "error",
                "message": "You do not have permission to create badges.",
            }
        ), 403
    data = await request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    # Create a new badge in the database
    await glob.db.execute(
        "INSERT INTO badges (name, description, priority) VALUES (%s, %s, %s)",
        (data["name"], data["description"], data["priority"]),
    )
    # Get the ID of the newly created badge
    result = await glob.db.fetch(
        f"SELECT id FROM badges WHERE name = '{data['name']}'",
    )

    new_badge_id = result["id"] if result else None

    # Check if the badge ID exists
    if not new_badge_id:
        return jsonify({"error": "Failed to create badge"}), 500

    # Add the badge styles to the database
    try:
        for style in data["styles"]:
            await glob.db.execute(
                "INSERT INTO badge_styles (badge_id, type, value) VALUES (%s, %s, %s)",
                (new_badge_id, style["type"], style["value"]),
            )
    except Exception as e:
        print("error: ", str(e))
        return jsonify({"error": str(e)}), 500

    return jsonify({"success": "Badge created successfully"}), 200


@admin.route("/beatmaps/<int:page>")
@admin.route("/beatmaps")
@error_catcher
async def beatmaps(page=None):
    """Render the beatmaps page of guweb's admin panel."""
    if not "authenticated" in session:
        return await flash("error", "Please login first.", "login")

    if not session["user_data"]["is_staff"]:
        return await flash("error", f"You have insufficient privileges.", "home")

    if Privileges.ManageBeatmaps not in GetPriv(session["user_data"]["priv"]):
        return await flash("error", f"You have insufficient privileges.", "home")

    if page == None or page < 1:
        page = 1

    items_per_page = 50
    offset = (page - 1) * items_per_page

    requests = await glob.db.fetchall(
        "SELECT * FROM map_requests WHERE active = 1 ORDER BY datetime DESC LIMIT %s OFFSET %s",
        (items_per_page, offset),
    )

    # Append map_info to each entry in requests
    for request in requests:
        user = await glob.db.fetch(
            "SELECT name, id, country FROM users WHERE id = %s",
            (request["player_id"],),
        )

        user_badges = await glob.db.fetchall(
            "SELECT badge_id FROM user_badges WHERE userid = %s",
            (request["player_id"],),
        )
        badges = []
        for user_badge in user_badges:
            badge_id = user_badge["badge_id"]

            badge = await glob.db.fetch(
                "SELECT * FROM badges WHERE id = %s",
                (badge_id,),
            )

            badge_styles = await glob.db.fetchall(
                "SELECT * FROM badge_styles WHERE badge_id = %s",
                (badge_id,),
            )

            badge = dict(badge)
            badge["styles"] = {style["type"]: style["value"] for style in badge_styles}

            badges.append(badge)

            # Sort the badges based on priority
            badges.sort(key=lambda x: x["priority"], reverse=True)
        request["player"] = user
        request["player"]["badges"] = badges
        try:
            map_info_and_diffs = await glob.db.fetchall(
                """
                SELECT *
                FROM maps
                WHERE id = %s OR set_id = (
                    SELECT set_id FROM maps WHERE id = %s
                )
                """,
                (request["map_id"], request["map_id"]),
            )
        except:
            klogging.log(
                f"Error fetching map info for request {request['id']}",
                klogging.Ansi.LRED,
                extra={
                    "request": request,
                },
            )
        try:
            request["map_info"] = next(
                (map for map in map_info_and_diffs if map["id"] == request["map_id"])
            )
        except Exception as e:
            klogging.log(
                f"Error fetching map info for request {request['id']}, Deleting Request",
                klogging.Ansi.LRED,
                extra={
                    "request": request,
                },
            )
            await glob.db.execute(
                "DELETE FROM map_requests WHERE id = %s",
                (request["id"],),
            )
        try:
            request["map_diffs"] = [
                map for map in map_info_and_diffs if map["id"] != request["map_id"]
            ]
        except:
            klogging.log(
                f"Error fetching map diffs for request {request['id']}",
                klogging.Ansi.LRED,
                extra={
                    "request": request,
                },
            )

        # Convert datetime objects to strings
        request["datetime"] = request["datetime"].strftime("%Y-%m-%d %H:%M:%S")
        request["map_info"]["last_update"] = request["map_info"][
            "last_update"
        ].strftime("%Y-%m-%d %H:%M:%S")
        for diff in request["map_diffs"]:
            try:
                diff["last_update"] = diff["last_update"].strftime("%Y-%m-%d %H:%M:%S")
            except Exception as e:
                klogging.log(
                    f"Error converting datetime to string for diff {diff['id']}",
                    klogging.Ansi.LRED,
                    extra={
                        "diff": diff,
                    },
                )

    # Return HTML response
    return await render_template(
        "admin/beatmaps.html",
        requests=requests,
        datetime=datetime,
        timeago=timeago,
        page=page,
    )


@admin.route("/stuffbroke")
@error_catcher
async def stuffbroke():
    if not "authenticated" in session:
        return await flash("error", "Please login first.", "login")

    if Privileges.Dangerous not in GetPriv(session["user_data"]["priv"]):
        return await flash("error", f"You have insufficient privileges.", "home")

    await glob.db.execute(
        f"""
    INSERT INTO server_data (type, value)
    VALUES ('breakevent', '{int(datetime.datetime.now().timestamp())}')
    ON DUPLICATE KEY UPDATE value = '{int(datetime.datetime.now().timestamp())}';
    """
    )
    return await frontend.home(flash="Successfully broke stuff.", status="success")


@admin.route("/test")
@error_catcher
async def test():
    if not "authenticated" in session:
        return await flash("error", "Please login first.", "login")

    if Privileges.Dangerous not in GetPriv(session["user_data"]["priv"]):
        return await flash("error", f"You have insufficient privileges.", "home")

    return await flash("success", "Successfully tested. Results: ", "home")
