# -*- coding: utf-8 -*-

__all__ = ()

import bcrypt
import hashlib
import os
import time
import orjson
from functools import wraps
from PIL import Image
from pathlib import Path
from quart import Blueprint, redirect, render_template, request, session, send_file
from quart import Quart, request, redirect, Response, g

from constants import regexes
from objects import glob
from objects import utils
from objects.privileges import Privileges
from objects.utils import flash
from objects.utils import flash_with_customizations
from objects.utils import klogging, error_catcher

VALID_MODES = frozenset({"std", "taiko", "catch", "mania"})
VALID_MODS = frozenset({"vn", "rx", "ap"})

frontend = Blueprint("frontend", __name__)

app = Quart(__name__)


@app.route("/api/<path:file_path>")
async def api_redirect(file_path):
    redirect_url = f"https://api.{glob.config.domain}/{file_path}"
    return redirect(redirect_url, code=301)


def login_required(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        if not session:
            return await flash(
                "error", "You must be logged in to access that page.", "login"
            )
        return await func(*args, **kwargs)

    return wrapper


@frontend.route("/b/<id>")
@frontend.route("/s/<sid>")
@frontend.route("/docs/<doc>")
@frontend.route("/docs")
@frontend.route("/home")
@frontend.route("/")
@error_catcher
async def home(doc=None, sid=None, id=None, flash=None, status=None):
    doc = doc
    sid = sid
    id = id
    status = status
    unix_timestamp = await glob.db.fetch(
        'SELECT * FROM server_data WHERE type = "breakevent"'
    )
    unix_timestamp = unix_timestamp["value"]
    dash_data = await glob.db.fetch(
        "SELECT COUNT(id) count, "
        "(SELECT name FROM users ORDER BY id DESC LIMIT 1) lastest_user, "
        "(SELECT COUNT(id) FROM users WHERE NOT priv & 1) banned "
        "FROM users"
    )
    newly_ranked = await glob.db.fetchall(
        "SELECT * FROM newly_ranked ORDER BY time DESC LIMIT 5"
    )
    for map in newly_ranked:
        try:
            try:
                map_info = await glob.db.fetch(
                    "SELECT server, id, set_id, artist, title, creator FROM maps WHERE id = %s",
                    [map["map_id"]],
                )
            except Exception as e:
                klogging.log(
                    f"Error fetching map info for newly ranked map: {e}",
                    klogging.Ansi.LRED,
                    extra={
                        "Newly Ranked Map": map,
                    },
                )

            if map_info is not None:
                map.update(map_info)

            try:
                map["diffs"] = await glob.db.fetchall(
                    "SELECT * FROM maps WHERE set_id = %s", [map["set_id"]]
                )
            except KeyError as e:
                if str(e) == "'set_id'":
                    klogging.log(
                        f"no set_id found when fetching newly ranked map <{[map['map_id']]}>, deleting entry",
                        klogging.Ansi.LRED,
                    )
                    await glob.db.execute(
                        "DELETE FROM newly_ranked WHERE map_id = %s", [map["map_id"]]
                    )
                else:
                    klogging.log(
                        f"Error fetching diffs for newly ranked map: {e}",
                        klogging.Ansi.LRED,
                        extra={
                            "Newly Ranked Map": map,
                        },
                    )
                g.type = KeyError
                raise

            try:
                map["mod"] = await glob.db.fetch(
                    "SELECT name, id, country, priv FROM users WHERE id = %s",
                    [map["mod_id"]],
                )
            except Exception as e:
                klogging.log(
                    f"Error fetching mod info for newly ranked map: {e}",
                    klogging.Ansi.LRED,
                    extra={
                        "Newly Ranked Map": map,
                    },
                )
        except:
            if g.type == KeyError:
                if str(e) == "'set_id'":
                    return await flash(
                        "error",
                        "Error fetching map information for a Newly Ranked Map, this has been automatically corrected. Please reload.",
                        "home",
                    )
            return await flash(
                "error", "Error fetching map information for a Newly Ranked Map", "home"
            )

    changelogs = await glob.db.fetchall(
        "SELECT * FROM changelog ORDER BY time DESC LIMIT 5"
    )
    for log in changelogs:
        try:
            poster = await glob.db.fetch(
                "SELECT name, id, country, priv FROM users WHERE id = %s",
                [log["poster"]],
            )
            poster_badges = await glob.db.fetchall(
                "SELECT badge_id FROM user_badges WHERE userid = %s",
                (log["poster"],),
            )
            badges = []
            for user_badge in poster_badges:
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
                badge["styles"] = {
                    style["type"]: style["value"] for style in badge_styles
                }
                badges.append(badge)
                # Sort the badges based on priority
                badges.sort(key=lambda x: x["priority"], reverse=True)
            poster["badges"] = badges
            log["poster"] = poster
        except:
            klogging.log(
                f"Error fetching a changelog author",
                klogging.Ansi.LRED,
                extra={
                    "Changelog": log,
                },
            )
            return await flash(
                "error",
                "Error fetching a changelog author, Please notify a Developer.",
                "home",
            )

    try:
        if glob.sys["globalNotice"] != "" or glob.sys["globalNotice"] != None:
            globalNotice = glob.sys["globalNotice"]
    except:
        globalNotice = None
        pass
    if flash is None:
        try:
            if glob.sys["isDevEnv"] == "True":
                flash = f"This Website is the Dev Environment and should not be used for active play, please play on <a href='https://{glob.config.official_domain}'>our Official Server</a>"
                status = "success"
        except:
            pass
        try:
            if glob.sys["maintenance"] == "True":
                flash = f"Website is currently under maintenence"
                status = "success"
        except:
            pass
    return await render_template(
        "home.html",
        unix_timestamp=unix_timestamp,
        changelogs=changelogs,
        rankedmaps=newly_ranked,
        doc=doc,
        dash_data=dash_data,
        globalNotice=globalNotice,
        flash=flash,
        status=status,
    )


@frontend.route("/home/account/edit")
@error_catcher
async def home_account_edit():
    return redirect(
        "/settings/profile",
    )


@frontend.route("/settings")
@frontend.route("/settings/profile")
@error_catcher
@login_required
async def settings_profile():
    return await render_template("settings/profile.html")


@frontend.route("/settings/profile", methods=["POST"])
@error_catcher
@login_required
async def settings_profile_post():
    form = await request.form

    new_name = form.get("username", type=str)
    new_email = form.get("email", type=str)
    new_hue = form.get("hue", type=int)

    if new_name is None or new_email is None:
        return await flash("error", "Invalid parameters.", "home")

    old_name = session["user_data"]["name"]
    old_email = session["user_data"]["email"]
    if "hue" not in session["user_data"] or session["user_data"]["hue"] is None:
        old_hue = 190
    else:
        old_hue = session["user_data"]["hue"]

    # no data has changed; deny post
    if new_name == old_name and new_email == old_email and new_hue == old_hue:
        return await flash("error", "No changes have been made.", "settings/profile")

    if new_name != old_name:
        if not session["user_data"]["is_donator"]:
            return await flash(
                "error",
                "Username changes are currently a supporter perk.",
                "settings/profile",
            )

        # Usernames must:
        # - be within 2-15 characters in length
        # - not contain both ' ' and '_', one is fine
        # - not be in the config's `disallowed_names` list
        # - not already be taken by another player
        if not regexes.username.match(new_name):
            return await flash(
                "error", "Your new username syntax is invalid.", "settings/profile"
            )

        if "_" in new_name and " " in new_name:
            return await flash(
                "error",
                'Your new username may contain "_" or " ", but not both.',
                "settings/profile",
            )

        if new_name in glob.config.disallowed_names:
            return await flash(
                "error",
                "Your new username isn't allowed; pick another.",
                "settings/profile",
            )

        if await glob.db.fetch("SELECT 1 FROM users WHERE name = %s", [new_name]):
            return await flash(
                "error",
                "Your new username already taken by another user.",
                "settings/profile",
            )

        safe_name = utils.get_safe_name(new_name)

        # username change successful
        await glob.db.execute(
            "UPDATE users " "SET name = %s, safe_name = %s " "WHERE id = %s",
            [new_name, safe_name, session["user_data"]["id"]],
        )

    if new_email != old_email:
        # Emails must:
        # - match the regex `^[^@\s]{1,200}@[^@\s\.]{1,30}\.[^@\.\s]{1,24}$`
        # - not already be taken by another player
        if not regexes.email.match(new_email):
            return await flash(
                "error", "Your new email syntax is invalid.", "settings/profile"
            )

        if await glob.db.fetch("SELECT 1 FROM users WHERE email = %s", [new_email]):
            return await flash(
                "error",
                "Your new email already taken by another user.",
                "settings/profile",
            )

        # email change successful
        await glob.db.execute(
            "UPDATE users " "SET email = %s " "WHERE id = %s",
            [new_email, session["user_data"]["id"]],
        )
    if new_hue < 0 or new_hue > 360:
        return await flash("error", "Your hue value is invalid.", "settings/profile")

    await glob.db.execute(
        "INSERT INTO user_customisations (userid, hue) "
        "VALUES (%s, %s) "
        "ON DUPLICATE KEY UPDATE hue = %s",
        [session["user_data"]["id"], new_hue, new_hue],
    )

    # logout
    session.pop("authenticated", None)
    session.pop("user_data", None)
    return await flash(
        "success", "Your username/email have been changed! Please login again.", "login"
    )


@frontend.route("/settings/avatar")
@error_catcher
@login_required
async def settings_avatar():
    return await render_template("settings/avatar.html")


@frontend.route("/settings/avatar", methods=["POST"])
@error_catcher
@login_required
async def settings_avatar_post():
    # constants
    MAX_IMAGE_SIZE = glob.config.max_image_size * 1024 * 1024
    if glob.config.seperate_data_path:
        AVATARS_PATH = f"./.data/b.py/avatars"
    else:
        AVATARS_PATH = f"{glob.config.path_to_gulag}.data/avatars"
    ALLOWED_EXTENSIONS = [".jpeg", ".jpg", ".png"]
    if session["user_data"]["is_donator"]:
        ALLOWED_EXTENSIONS.append(".gif")
        MAX_IMAGE_SIZE = glob.config.max_image_size_supporter * 1024 * 1024

    avatar = (await request.files).get("avatar")

    # no file uploaded; deny post
    if avatar is None or not avatar.filename:
        return await flash("error", "No image was selected!", "settings/avatar")

    filename, file_extension = os.path.splitext(avatar.filename.lower())

    # bad file extension; deny post
    if (
        not file_extension in ALLOWED_EXTENSIONS
        and not session["user_data"]["is_donator"]
    ):
        if file_extension == ".gif":
            return await flash(
                "error", "Only donators can use .gif avatars!", "settings/avatar"
            )
        else:
            return await flash(
                "error",
                "The image you select must be either a .JPG, .JPEG, or .PNG file!",
                "settings/avatar",
            )
    elif (
        not file_extension in ALLOWED_EXTENSIONS and session["user_data"]["is_donator"]
    ):
        return await flash(
            "error",
            "The image you select must be either a .JPG, .JPEG, .PNG or .GIF file!",
            "settings/avatar",
        )

    # check file size of avatar
    if (
        avatar.content_length > MAX_IMAGE_SIZE
        and not session["user_data"]["is_donator"]
    ):
        return await flash(
            "error",
            "The image you selected is too large! become a donor to get double the size!",
            "settings/avatar",
        )
    elif avatar.content_length > MAX_IMAGE_SIZE and session["user_data"]["is_donator"]:
        return await flash(
            "error", "The image you selected is too large!", "settings/avatar"
        )

    # remove old avatars
    for fx in ALLOWED_EXTENSIONS:
        if os.path.isfile(
            f'{AVATARS_PATH}/{session["user_data"]["id"]}{fx}'
        ):  # Checking file e
            os.remove(f'{AVATARS_PATH}/{session["user_data"]["id"]}{fx}')

    if file_extension.lower() != ".gif":
        # avatar cropping to 1:1 for non-animated images
        pilavatar = Image.open(avatar.stream)
        pilavatar = utils.crop_image(pilavatar)
        try:
            pilavatar.save(
                os.path.join(
                    AVATARS_PATH,
                    f'{session["user_data"]["id"]}{file_extension.lower()}',
                )
            )
        except Exception as e:
            klogging.log(f"Error saving avatar: {e}", klogging.Ansi.LRED)
            return await flash("error", f"Error saving avatar", "settings/avatar")
    else:
        # Handle GIF images (no processing)
        save_path = os.path.join(AVATARS_PATH, f'{session["user_data"]["id"]}.gif')
        try:
            with open(save_path, "wb") as output_file:
                output_file.write(avatar.read())
        except Exception as e:
            klogging.log(f"Error saving avatar: {e}", klogging.Ansi.LRED)
            return await flash("error", f"Error saving avatar", "settings/avatar")

    return await flash(
        "success", "Your avatar has been successfully changed!", "settings/avatar"
    )


@frontend.route("/settings/custom")
@error_catcher
@login_required
async def settings_custom():
    profile_customizations = utils.has_profile_customizations(
        session["user_data"]["id"]
    )
    return await render_template(
        "settings/custom.html", customizations=profile_customizations
    )


@frontend.route("/settings/custom", methods=["POST"])
@error_catcher
@login_required
async def settings_custom_post():
    files = await request.files
    banner = files.get("banner")
    background = files.get("background")
    ALLOWED_EXTENSIONS = [".jpeg", ".jpg", ".png"]
    if session["user_data"]["is_donator"]:
        ALLOWED_EXTENSIONS.append(".gif")

    # no file uploaded; deny post
    if banner is None and background is None:
        return await flash_with_customizations(
            "error", "No image was selected!", "settings/custom"
        )

    query = "SELECT COUNT(*) FROM user_customisations WHERE userid = %s"
    row = await glob.db.fetch(query, [session["user_data"]["id"]])
    user_has_customisations_entry = row["COUNT(*)"]
    print(user_has_customisations_entry)
    if banner is not None and banner.filename:
        _, file_extension = os.path.splitext(banner.filename.lower())
        if (
            not file_extension in ALLOWED_EXTENSIONS
            and not session["user_data"]["is_donator"]
        ):
            if file_extension == ".gif":
                return await flash_with_customizations(
                    "error", "Only donators can use .gif banners!", "settings/custom"
                )
            else:
                return await flash_with_customizations(
                    "error",
                    f"The banner you select must be either a .JPG, .JPEG, or .PNG file!",
                    "settings/custom",
                )
        elif (
            not file_extension in ALLOWED_EXTENSIONS
            and session["user_data"]["is_donator"]
        ):
            return await flash_with_customizations(
                "error",
                f"The banner you select must be either a .JPG, .JPEG, .PNG or .GIF file!",
                "settings/custom",
            )

        banner_file_no_ext = os.path.join(
            f".data/banners", f'{session["user_data"]["id"]}'
        )

        # remove old picture
        for ext in ALLOWED_EXTENSIONS:
            banner_file_with_ext = f"{banner_file_no_ext}{ext}"
            if os.path.isfile(banner_file_with_ext):
                os.remove(banner_file_with_ext)

        await banner.save(f"{banner_file_no_ext}{file_extension}")
        try:
            if user_has_customisations_entry == 1:
                await glob.db.execute(
                    "UPDATE user_customisations "
                    "SET has_banner = 1 "
                    "WHERE userid = %s",
                    [session["user_data"]["id"]],
                )
            else:
                await glob.db.execute(
                    "INSERT INTO user_customisations "
                    "(userid, has_banner) "
                    "VALUES (%s, 1)",
                    [session["user_data"]["id"]],
                )
        except Exception as e:
            return await flash_with_customizations(
                "error", f"Error updating banner in database: {e}", "settings/custom"
            )

    if background is not None and background.filename:
        _, file_extension = os.path.splitext(background.filename.lower())
        if (
            not file_extension in ALLOWED_EXTENSIONS
            and session["user_data"]["is_donator"]
        ):
            return await flash_with_customizations(
                "error",
                f"The background you select must be either a .JPG, .JPEG, .PNG or .GIF file!",
                "settings/custom",
            )
        elif (
            not file_extension in ALLOWED_EXTENSIONS
            and not session["user_data"]["is_donator"]
        ):
            if file_extension == ".gif":
                return await flash_with_customizations(
                    "error",
                    "Only donators can use .gif backgrounds!",
                    "settings/custom",
                )
            return await flash_with_customizations(
                "error",
                f"The background you select must be either a .JPG, .JPEG, or .PNG file!",
                "settings/custom",
            )

        background_file_no_ext = os.path.join(
            f".data/backgrounds", f'{session["user_data"]["id"]}'
        )

        # remove old picture
        for ext in ALLOWED_EXTENSIONS:
            background_file_with_ext = f"{background_file_no_ext}{ext}"
            if os.path.isfile(background_file_with_ext):
                os.remove(background_file_with_ext)

        await background.save(f"{background_file_no_ext}{file_extension}")
        try:
            if user_has_customisations_entry == 1:
                await glob.db.execute(
                    "UPDATE user_customisations "
                    "SET has_background = 1 "
                    "WHERE userid = %s",
                    [session["user_data"]["id"]],
                )
            else:
                await glob.db.execute(
                    "INSERT INTO user_customisations "
                    "(userid, has_background) "
                    "VALUES (%s, 1)",
                    [session["user_data"]["id"]],
                )
        except Exception as e:
            return await flash_with_customizations(
                "error",
                f"Error updating background in database: {e}",
                "settings/custom",
            )

    return await flash_with_customizations(
        "success",
        "Your customisation has been successfully changed!",
        "settings/custom",
    )


@frontend.route("/settings/password")
@error_catcher
@login_required
async def settings_password():
    return await render_template("settings/password.html")


@frontend.route("/settings/password", methods=["POST"])
@error_catcher
@login_required
async def settings_password_post():
    form = await request.form
    old_password = form.get("old_password")
    new_password = form.get("new_password")
    repeat_password = form.get("repeat_password")

    # new password and repeat password don't match; deny post
    if new_password != repeat_password:
        return await flash(
            "error",
            "Your new password doesn't match your repeated password!",
            "settings/password",
        )

    # new password and old password match; deny post
    if old_password == new_password:
        return await flash(
            "error",
            "Your new password cannot be the same as your old password!",
            "settings/password",
        )

    # Passwords must:
    # - be within 8-32 characters in length
    # - have more than 3 unique characters
    # - not be in the config's `disallowed_passwords` list
    if not 8 < len(new_password) <= 32:
        return await flash(
            "error",
            "Your new password must be 8-32 characters in length.",
            "settings/password",
        )

    if len(set(new_password)) <= 3:
        return await flash(
            "error",
            "Your new password must have more than 3 unique characters.",
            "settings/password",
        )

    if new_password.lower() in glob.config.disallowed_passwords:
        return await flash(
            "error", "Your new password was deemed too simple.", "settings/password"
        )

    # cache and other password related information
    bcrypt_cache = glob.cache["bcrypt"]
    pw_bcrypt = (
        await glob.db.fetch(
            "SELECT pw_bcrypt " "FROM users " "WHERE id = %s",
            [session["user_data"]["id"]],
        )
    )["pw_bcrypt"].encode()

    pw_md5 = hashlib.md5(old_password.encode()).hexdigest().encode()

    # check old password against db
    # intentionally slow, will cache to speed up
    if pw_bcrypt in bcrypt_cache:
        if pw_md5 != bcrypt_cache[pw_bcrypt]:  # ~0.1ms
            if glob.config.debug:
                klogging.log(
                    f"{session['user_data']['name']}'s change pw failed - pw incorrect.",
                    klogging.Ansi.LYELLOW,
                )
            return await flash(
                "error", "Your old password is incorrect.", "settings/password"
            )
    else:  # ~200ms
        if not bcrypt.checkpw(pw_md5, pw_bcrypt):
            if glob.config.debug:
                klogging.log(
                    f"{session['user_data']['name']}'s change pw failed - pw incorrect.",
                    klogging.Ansi.LYELLOW,
                )
            return await flash(
                "error", "Your old password is incorrect.", "settings/password"
            )

    # remove old password from cache
    if pw_bcrypt in bcrypt_cache:
        del bcrypt_cache[pw_bcrypt]

    # calculate new md5 & bcrypt pw
    pw_md5 = hashlib.md5(new_password.encode()).hexdigest().encode()
    pw_bcrypt = bcrypt.hashpw(pw_md5, bcrypt.gensalt())

    # update password in cache and db
    bcrypt_cache[pw_bcrypt] = pw_md5
    await glob.db.execute(
        "UPDATE users " "SET pw_bcrypt = %s " "WHERE safe_name = %s",
        [pw_bcrypt, utils.get_safe_name(session["user_data"]["name"])],
    )

    # logout
    session.pop("authenticated", None)
    session.pop("user_data", None)
    return await flash(
        "success", "Your password has been changed! Please log in again.", "login"
    )


@frontend.route("/settings/ordr")
@error_catcher
@login_required
async def settings_ordr():
    return await render_template("settings/ordr.html")


@frontend.route("/settings/ordr", methods=["POST"])
@error_catcher
@login_required
async def settings_ordr_post():
    form = await request.form
    skin = form.get("skin")

    await glob.db.execute(
        "UPDATE users_ordr " "SET skin = %s " "WHERE userid = %s",
        [skin, session["user_data"]["id"]],
    )

    return await flash("success", "Your O!RDR Settings have been saved", "home")


@frontend.route("/u/<id>")
@error_catcher
async def profile_select(id):
    mode = request.args.get("mode", "std", type=str)  # 1. key 2. default value
    mods = request.args.get("mods", "vn", type=str)
    user_data = await glob.db.fetch(
        "SELECT users.name, users.safe_name, users.id, users.priv, users.country, user_customisations.hue "
        "FROM users "
        "LEFT JOIN user_customisations ON users.id = user_customisations.userid "
        "WHERE users.safe_name = %s OR users.id = %s LIMIT 1",
        [utils.get_safe_name(id), id],
    )

    # no user
    if not user_data:
        return (await render_template("404.html"), 404)

    # make sure mode & mods are valid args
    if mode is not None and mode not in VALID_MODES:
        return (await render_template("404.html"), 404)

    if mods is not None and mods not in VALID_MODS:
        return (await render_template("404.html"), 404)

    is_staff = "authenticated" in session and session["user_data"]["is_staff"]
    if not user_data or not (user_data["priv"] & Privileges.Normal or is_staff):
        return (await render_template("404.html"), 404)

    user_data["customisation"] = utils.has_profile_customizations(user_data["id"])

    g.Player = {
        "id": user_data["id"],
        "name": user_data["name"],
        "country": user_data["country"],
    }
    try:
        if glob.sys["globalNotice"] != "" or glob.sys["globalNotice"] != None:
            globalNotice = glob.sys["globalNotice"]
    except:
        globalNotice = None
        pass
    try:
        if (glob.sys["isDevEnv"]) == "True":
            return await render_template(
                "profile.html",
                user=user_data,
                mode=mode,
                mods=mods,
                globalNotice=globalNotice,
                flash=f"This Website is the Dev Environment and should not be used for active play, please play on <a href='https://{glob.config.official_domain}'>our Official Server</a>",
                status="success",
            )
    except:
        pass
    try:
        if (glob.sys["maintenance"]) == "True":
            return await render_template(
                "profile.html",
                user=user_data,
                mode=mode,
                mods=mods,
                globalNotice=globalNotice,
                flash="Website is currently under maintenence",
                status="success",
            )
    except:
        pass
    return await render_template(
        "profile.html", user=user_data, mode=mode, mods=mods, globalNotice=globalNotice
    )


@frontend.route("/leaderboard")
@frontend.route("/lb")
@frontend.route("/leaderboard/<mode>/<sort>/<mods>")
@frontend.route("/lb/<mode>/<sort>/<mods>")
@error_catcher
async def leaderboard(mode="std", sort="pp", mods="vn"):
    try:
        if glob.sys["globalNotice"] != "" or glob.sys["globalNotice"] != None:
            globalNotice = glob.sys["globalNotice"]
    except:
        globalNotice = None
        pass
    try:
        if (glob.sys["isDevEnv"]) == "True":
            return await render_template(
                "leaderboard.html",
                mode=mode,
                sort=sort,
                mods=mods,
                globalNotice=globalNotice,
                flash=f"This Website is the Dev Environment and should not be used for active play, please play on <a href='https://{glob.config.official_domain}'>our Official Server</a>",
                status="success",
            )
    except:
        pass
    try:
        if (glob.sys["maintenance"]) == "True":
            return await render_template(
                "leaderboard.html",
                mode=mode,
                sort=sort,
                mods=mods,
                globalNotice=globalNotice,
                flash="Website is currently under maintenence",
                status="success",
            )
    except:
        pass
    return await render_template(
        "leaderboard.html", mode=mode, sort=sort, mods=mods, globalNotice=globalNotice
    )


@frontend.route("/clans")
@error_catcher
async def clans():
    try:
        if glob.sys["globalNotice"] != "" or glob.sys["globalNotice"] != None:
            globalNotice = glob.sys["globalNotice"]
    except:
        globalNotice = None
        pass
    try:
        if glob.sys["isDevEnv"] == "True":
            return await render_template(
                "clans.html",
                globalNotice=globalNotice,
                flash=f"This Website is the Dev Environment and should not be used for active play, please play on <a href='https://{glob.config.official_domain}'>our Official Server</a>",
                status="success",
            )
    except:
        pass
    try:
        if glob.sys["maintenance"] == "True":
            return await render_template(
                "clans.html",
                globalNotice=globalNotice,
                flash="Website is currently under maintenence",
                status="success",
            )
    except:
        pass
    return await render_template("clans.html", globalNotice=globalNotice)


@frontend.route("/login")
@error_catcher
async def login():
    if "authenticated" in session:
        return await flash("error", "You're already logged in!", "home")
    try:
        if glob.sys["globalNotice"] != "" or glob.sys["globalNotice"] != None:
            globalNotice = glob.sys["globalNotice"]
    except:
        globalNotice = None
        pass
    try:
        if glob.sys["isDevEnv"] == "True":
            return await render_template(
                "login.html",
                globalNotice=globalNotice,
                flash=f"This Website is the Dev Environment and should not be used for active play, please play on <a href='https://{glob.config.official_domain}'>our Official Server</a>",
                status="success",
            )
    except:
        pass
    try:
        if glob.sys["maintenance"] == "True":
            return await render_template(
                "login.html",
                globalNotice=globalNotice,
                flash="Website is currently under maintenence",
                status="success",
            )
    except:
        pass
    return await render_template("login.html", globalNotice=globalNotice)


@frontend.route("/login", methods=["POST"])
@error_catcher
async def login_post():
    if "authenticated" in session:
        return await flash("error", "You're already logged in!", "home")

    if glob.config.debug:
        login_time = time.time_ns()

    form = await request.form
    username = form.get("username", type=str)
    passwd_txt = form.get("password", type=str)

    if username is None or passwd_txt is None:
        return await flash("error", "Invalid parameters.", "home")

    # check if account exists
    user_info = await glob.db.fetch(
        "SELECT users.id, users.name, users.email, users.priv, "
        "users.pw_bcrypt, users.silence_end, user_customisations.hue "
        "FROM users "
        "LEFT JOIN user_customisations ON users.id = user_customisations.userid "
        "WHERE users.safe_name = %s",
        [utils.get_safe_name(username)],
    )
    badges = []
    if user_info is not None and user_info["id"] is not None:
        # Select badge_id from user_badges where userid = user_id
        user_badges = await glob.db.fetchall(
            "SELECT badge_id FROM user_badges WHERE userid = %s", [user_info["id"]]
        )
        for user_badge in user_badges:
            badge_id = user_badge["badge_id"]

            badge = await glob.db.fetch(
                "SELECT * FROM badges WHERE id = %s", [badge_id]
            )

            badge_styles = await glob.db.fetchall(
                "SELECT * FROM badge_styles WHERE badge_id = %s", [badge_id]
            )

            badge = dict(badge)
            badge["styles"] = {style["type"]: style["value"] for style in badge_styles}

            badges.append(badge)

            # Sort the badges based on priority
            badges.sort(key=lambda x: x["priority"], reverse=True)
    # user doesn't exist; deny post
    # NOTE: Bot isn't a user.
    if not user_info or user_info["id"] == 1:
        if glob.config.debug:
            klogging.log(
                f"{username}'s login failed - account doesn't exist.",
                klogging.Ansi.LYELLOW,
            )
        return await flash("error", "Account does not exist.", "login")

    # cache and other related password information
    bcrypt_cache = glob.cache["bcrypt"]
    pw_bcrypt = user_info["pw_bcrypt"].encode()
    pw_md5 = hashlib.md5(passwd_txt.encode()).hexdigest().encode()

    # check credentials (password) against db
    # intentionally slow, will cache to speed up
    if pw_bcrypt in bcrypt_cache:
        if pw_md5 != bcrypt_cache[pw_bcrypt]:  # ~0.1ms
            if glob.config.debug:
                klogging.log(
                    f"{username}'s login failed - pw incorrect.", klogging.Ansi.LYELLOW
                )
            return await flash("error", "Password is incorrect.", "login")
    else:  # ~200ms
        if not bcrypt.checkpw(pw_md5, pw_bcrypt):
            if glob.config.debug:
                klogging.log(
                    f"{username}'s login failed - pw incorrect.", klogging.Ansi.LYELLOW
                )
            return await flash("error", "Password is incorrect.", "login")

        # login successful; cache password for next login
        bcrypt_cache[pw_bcrypt] = pw_md5

    # user not verified; render verify
    if not user_info["priv"] & Privileges.Verified:
        if glob.config.debug:
            klogging.log(
                f"{username}'s login failed - not verified.", klogging.Ansi.LYELLOW
            )
        return await render_template("verify.html")

    # user banned; deny post
    if not user_info["priv"] & Privileges.Normal:
        if glob.config.debug:
            klogging.log(f"{username}'s login failed - banned.", klogging.Ansi.RED)
        return await flash(
            "error",
            "Your account is restricted. You are not allowed to log in.",
            "login",
        )

    # login successful; store session data
    if glob.config.debug:
        klogging.log(f"{username}'s login succeeded.", klogging.Ansi.LGREEN)

    session["authenticated"] = True
    session["user_data"] = {
        "id": user_info["id"],
        "name": user_info["name"],
        "badges": (badges or None),
        "email": user_info["email"],
        "priv": user_info["priv"],
        "silence_end": user_info["silence_end"],
        "is_staff": user_info["priv"] & Privileges.Staff != 0,
        "is_dev": user_info["priv"] & Privileges.Dangerous != 0,
        "is_donator": user_info["priv"] & Privileges.Donator != 0,
        "hue": user_info["hue"] or None,
    }

    if glob.config.debug:
        login_time = (time.time_ns() - login_time) / 1e6
        klogging.log(f"Login took {login_time:.2f}ms!", klogging.Ansi.LYELLOW)
    g.Player = {
        "id": user_info["id"],
        "name": user_info["name"],
        "is_staff": user_info["priv"] & Privileges.Staff != 0,
        "is_dev": user_info["priv"] & Privileges.Dangerous != 0,
        "is_donator": user_info["priv"] & Privileges.Donator != 0,
        "priv": user_info["priv"],
    }
    return await home(status="success", flash=f"Hey, welcome back {username}!")


@frontend.route("/register")
@error_catcher
async def register():
    if "authenticated" in session:
        return await flash("error", "You're already logged in.", "home")

    if not glob.config.registration:
        return await flash("error", "Registrations are currently disabled.", "home")

    try:
        if glob.sys["globalNotice"] != "" or glob.sys["globalNotice"] != None:
            globalNotice = glob.sys["globalNotice"]
    except:
        globalNotice = None
        pass
    try:
        if glob.sys["isDevEnv"] == "True":
            return await render_template(
                "register.html",
                globalNotice=globalNotice,
                flash=f"This Website is the Dev Environment and should not be used for active play, please play on <a href='https://{glob.config.official_domain}'>our Official Server</a>",
                status="success",
            )
    except:
        pass
    try:
        if glob.sys["maintenance"] == "True":
            return await render_template(
                "register.html",
                globalNotice=globalNotice,
                flash="Website is currently under maintenence",
                status="success",
            )
    except:
        pass
    return await render_template("register.html", globalNotice=globalNotice)


@frontend.route("/register", methods=["POST"])
@error_catcher
async def register_post():
    if "authenticated" in session:
        return await flash("error", "You're already logged in.", "home")

    if not glob.config.registration:
        return await flash("error", "Registrations are currently disabled.", "home")

    form = await request.form
    username = form.get("username", type=str)
    email = form.get("email", type=str)
    passwd_txt = form.get("password", type=str)

    if username is None or email is None or passwd_txt is None:
        return await flash("error", "Invalid parameters.", "home")

    if glob.config.hCaptcha_sitekey != "changeme":
        captcha_data = form.get("h-captcha-response", type=str)
        if captcha_data is None or not await utils.validate_captcha(captcha_data):
            return await flash("error", "Captcha failed.", "register")

    # Usernames must:
    # - be within 2-15 characters in length
    # - not contain both ' ' and '_', one is fine
    # - not be in the config's `disallowed_names` list
    # - not already be taken by another player
    # check if username exists
    if not regexes.username.match(username):
        return await flash("error", "Invalid username syntax.", "register")

    if "_" in username and " " in username:
        return await flash(
            "error", 'Username may contain "_" or " ", but not both.', "register"
        )

    if username in glob.config.disallowed_names:
        return await flash("error", "Disallowed username; pick another.", "register")

    if await glob.db.fetch("SELECT 1 FROM users WHERE name = %s", username):
        return await flash(
            "error", "Username already taken by another user.", "register"
        )

    # Emails must:
    # - match the regex `^[^@\s]{1,200}@[^@\s\.]{1,30}\.[^@\.\s]{1,24}$`
    # - not already be taken by another player
    if not regexes.email.match(email):
        return await flash("error", "Invalid email syntax.", "register")

    if await glob.db.fetch("SELECT 1 FROM users WHERE email = %s", email):
        return await flash("error", "Email already taken by another user.", "register")

    # Passwords must:
    # - be within 8-32 characters in length
    # - have more than 3 unique characters
    # - not be in the config's `disallowed_passwords` list
    if not 8 <= len(passwd_txt) <= 32:
        return await flash(
            "error", "Password must be 8-32 characters in length.", "register"
        )

    if len(set(passwd_txt)) <= 3:
        return await flash(
            "error", "Password must have more than 3 unique characters.", "register"
        )

    if passwd_txt.lower() in glob.config.disallowed_passwords:
        return await flash("error", "That password was deemed too simple.", "register")

    # TODO: add correct locking
    # (start of lock)
    pw_md5 = hashlib.md5(passwd_txt.encode()).hexdigest().encode()
    pw_bcrypt = bcrypt.hashpw(pw_md5, bcrypt.gensalt())
    glob.cache["bcrypt"][pw_bcrypt] = pw_md5  # cache pw

    safe_name = utils.get_safe_name(username)

    # fetch the users' country
    if (
        request.headers
        and (ip := request.headers.get("X-Real-IP", type=str)) is not None
    ):
        country = await utils.fetch_geoloc(ip)
    else:
        country = "xx"

    async with glob.db.pool.acquire() as conn:
        async with conn.cursor() as db_cursor:
            # add to `users` table.
            await db_cursor.execute(
                "INSERT INTO users "
                "(name, safe_name, email, pw_bcrypt, country, creation_time, latest_activity) "
                "VALUES (%s, %s, %s, %s, %s, UNIX_TIMESTAMP(), UNIX_TIMESTAMP())",
                [username, safe_name, email, pw_bcrypt, country],
            )
            user_id = db_cursor.lastrowid

            # add to `stats` table.
            await db_cursor.executemany(
                "INSERT INTO stats " "(id, mode) VALUES (%s, %s)",
                [
                    (user_id, mode)
                    for mode in (
                        0,  # vn!std
                        1,  # vn!taiko
                        2,  # vn!catch
                        3,  # vn!mania
                        4,  # rx!std
                        5,  # rx!taiko
                        6,  # rx!catch
                        8,  # ap!std
                    )
                ],
            )

    # (end of lock)

    if glob.config.debug:
        klogging.log(
            f"{username} has registered - awaiting verification.", klogging.Ansi.LGREEN
        )

    # user has successfully registered
    return await render_template("verify.html")


@frontend.route("/logout")
@error_catcher
async def logout():
    if "authenticated" not in session:
        return await flash(
            "error", "You can't logout if you aren't logged in!", "login"
        )

    if glob.config.debug:
        klogging.log(
            f'{session["user_data"]["name"]} logged out.', klogging.Ansi.LGREEN
        )

    # clear session data
    session.pop("authenticated", None)
    session.pop("user_data", None)

    # render login
    return await flash("success", "Successfully logged out!", "login")


@frontend.route("/changelog")
@frontend.route("/changelog/<type>/<category>")
@error_catcher
async def changelog(type="frontend", category="all"):
    changelogs = await glob.db.fetchall("SELECT * FROM changelog ORDER BY 'time' DESC")
    for log in changelogs:
        poster = await glob.db.fetch(
            "SELECT name, id, country, priv FROM users WHERE id = %s", [log["poster"]]
        )
        poster_badges = await glob.db.fetchall(
            "SELECT badge_id FROM user_badges WHERE userid = %s",
            (log["poster"],),
        )
        badges = []
        for user_badge in poster_badges:
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
        poster["badges"] = badges
        log["poster"] = poster

    try:
        if glob.sys["globalNotice"] != "" or glob.sys["globalNotice"] != None:
            globalNotice = glob.sys["globalNotice"]
    except:
        globalNotice = None
        pass
    try:
        if (glob.sys["isDevEnv"]) == "True":
            return await render_template(
                "changelog.html",
                changelogs=changelogs,
                type=type,
                category=category,
                globalNotice=globalNotice,
                flash=f"This Website is the Dev Environment and should not be used for active play, please play on <a href='https://{glob.config.official_domain}'>our Official Server</a>",
                status="success",
            )
    except:
        pass
    try:
        if (glob.sys["maintenance"]) == "True":
            return await render_template(
                "changelog.html",
                changelogs=changelogs,
                type=type,
                category=category,
                globalNotice=globalNotice,
                flash="Website is currently under maintenence",
                status="success",
            )
    except:
        pass
    return await render_template(
        "changelog.html",
        changelogs=changelogs,
        type=type,
        category=category,
        globalNotice=globalNotice,
    )


# social media redirections


@frontend.route("/github")
@frontend.route("/gh")
async def github_redirect():
    return redirect(glob.config.github)


@frontend.route("/discord")
async def discord_redirect():
    return redirect(glob.config.discord_server)


@frontend.route("/youtube")
@frontend.route("/yt")
async def youtube_redirect():
    return redirect(glob.config.youtube)


@frontend.route("/twitter")
async def twitter_redirect():
    return redirect(glob.config.twitter)


@frontend.route("/instagram")
@frontend.route("/ig")
async def instagram_redirect():
    return redirect(glob.config.instagram)


# profile customisation
BANNERS_PATH = Path.cwd() / ".data/banners"
BACKGROUND_PATH = Path.cwd() / ".data/backgrounds"


@frontend.route("/banners/<user_id>")
@error_catcher
async def get_profile_banner(user_id: int):
    # Check if avatar exists
    for ext in ("jpg", "jpeg", "png", "gif"):
        path = BANNERS_PATH / f"{user_id}.{ext}"
        if path.exists():
            return await send_file(path)

    return b'{"status":404}'


@frontend.route("/backgrounds/<user_id>")
@error_catcher
async def get_profile_background(user_id: int):
    # Check if avatar exists
    for ext in ("jpg", "jpeg", "png", "gif"):
        path = BACKGROUND_PATH / f"{user_id}.{ext}"
        if path.exists():
            return await send_file(path)

    return b'{"status":404}'
