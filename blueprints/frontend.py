# -*- coding: utf-8 -*-

__all__ = ()

import bcrypt
import hashlib
import io
import json
import os
import time
import re
import orjson
from functools import wraps
from PIL import Image
from pathlib import Path
from quart import Blueprint, redirect, render_template, request, session, send_file, Response
from quart import jsonify, g

from constants import regexes
from objects import glob
from objects import utils
from objects.privileges import Privileges
from objects.utils import flash
from objects.utils import flash_with_customizations
from objects.utils import klogging, error_catcher

VALID_MODES = frozenset({'std', 'taiko', 'catch', 'mania'})
VALID_MODS = frozenset({'vn', 'rx', 'ap'})

frontend = Blueprint('frontend', __name__)

# --- Security & Helper Middleware ---

SAFE_API_PATH_REGEX = re.compile(r'^[a-zA-Z0-9_/-]+$')

@frontend.route("/api/<path:file_path>")
async def api_redirect(file_path):
    # SECURITY: Validate path to prevent open redirects or internal access
    if not SAFE_API_PATH_REGEX.match(file_path):
        return await flash('error', 'Invalid API path requested.', 'home')
        
    redirect_url = f"https://api.{glob.config.domain}/{file_path}"
    return redirect(redirect_url, code=301)

@frontend.route("/health")
async def health_check():
    """Robust health check endpoint for Docker health checks.
    
    Checks:
    - Database connectivity
    - Redis connectivity
    - Returns JSON response with status and details
    """
    start_time = time.time()
    health_status = {
        "status": "healthy",
        "timestamp": time.time(),
        "service": "kawaweb",
        "checks": {},
        "response_time_ms": 0
    }
    
    # Check database connectivity
    try:
        db_start = time.time()
        db_healthy = await glob.db.fetch("SELECT 1") is not None
        db_time = (time.time() - db_start) * 1000
        
        if db_healthy:
            health_status["checks"]["database"] = {
                "status": "connected",
                "response_time_ms": round(db_time, 2)
            }
        else:
            health_status["status"] = "unhealthy"
            health_status["checks"]["database"] = {
                "status": "disconnected",
                "response_time_ms": round(db_time, 2)
            }
    except Exception as e:
        klogging.log(f"Health check - database failed: {e}", klogging.Ansi.LRED)
        health_status["status"] = "unhealthy"
        health_status["checks"]["database"] = {
            "status": "failed",
            "error": "unavailable"
        }

    # Check Redis connectivity
    try:
        redis_start = time.time()
        redis_healthy = await glob.redis.ping()
        redis_time = (time.time() - redis_start) * 1000
        
        if redis_healthy:
            health_status["checks"]["redis"] = {
                "status": "connected",
                "response_time_ms": round(redis_time, 2)
            }
        else:
            health_status["status"] = "unhealthy"
            health_status["checks"]["redis"] = {
                "status": "disconnected",
                "response_time_ms": round(redis_time, 2)
            }
    except Exception as e:
        klogging.log(f"Health check - redis failed: {e}", klogging.Ansi.LRED)
        health_status["status"] = "unhealthy"
        health_status["checks"]["redis"] = {
            "status": "failed",
            "error": "unavailable"
        }

    # Calculate total response time
    health_status["response_time_ms"] = round((time.time() - start_time) * 1000, 2)
    
    # Determine HTTP status code
    status_code = 200 if health_status["status"] == "healthy" else 503
    
    # Return JSON response
    return Response(
        response=json.dumps(health_status),
        status=status_code,
        content_type="application/json"
    )

@frontend.before_request
async def inject_globals():
    """
    Injects global system variables (notices, maintenance mode) into the request context.
    This prevents code duplication in every route.
    """
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
        klogging.log(f"Error accessing glob.sys: {e}", klogging.Ansi.LRED)

def login_required(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        if not session or 'authenticated' not in session:
            return await flash('error', 'You must be logged in to access that page.', 'hinaDir/login')
        return await func(*args, **kwargs)
    return wrapper

# --- Routes ---

@frontend.route('/b/<id>')
@frontend.route('/s/<sid>')
@frontend.route('/docs/<doc>')
@frontend.route('/docs')
@frontend.route('/home')
@frontend.route('/')
@error_catcher
async def home(doc=None, sid=None, id=None, flash=None, status=None):
    unix_timestamp = await glob.db.fetch('SELECT * FROM server_data WHERE type = "breakevent"')
    unix_timestamp = unix_timestamp['value']
    
    dash_data = await glob.db.fetch(
        'SELECT COUNT(id) count, '
        '(SELECT name FROM users ORDER BY id DESC LIMIT 1) lastest_user, '
        '(SELECT COUNT(id) FROM users WHERE NOT priv & 1) banned '
        'FROM users'
    )
    
    newly_ranked = await glob.db.fetchall('SELECT * FROM newly_ranked ORDER BY time DESC LIMIT 6')
    
    # Process newly ranked maps
    for map in newly_ranked:
        try:
            map_info = await glob.db.fetch(
                'SELECT server, id, set_id, artist, title, creator FROM maps WHERE id = %s', 
                [map['map_id']]
            )
            
            if map_info:
                map.update(map_info)
                # Fetch diffs
                map['diffs'] = await glob.db.fetchall('SELECT * FROM maps WHERE set_id = %s', [map['set_id']])
                
                # Fetch mod info
                map['mod'] = await glob.db.fetch('SELECT name, id, country, priv FROM users WHERE id = %s', [map['mod_id']])
            else:
                # Map info missing, clean up DB
                klogging.log(f"Map info missing for newly ranked map {map['map_id']}, deleting.", klogging.Ansi.LRED)
                await glob.db.execute('DELETE FROM newly_ranked WHERE map_id = %s', [map['map_id']])
                continue

        except KeyError as e:
            if str(e) == "'set_id'":
                klogging.log(f"No set_id for map {map['map_id']}, deleting entry.", klogging.Ansi.LRED)
                await glob.db.execute('DELETE FROM newly_ranked WHERE map_id = %s', [map['map_id']])
            else:
                klogging.log(f"KeyError in home route: {e}", klogging.Ansi.LRED)
            continue
        except Exception as e:
            klogging.log(f"Unexpected error in home route: {e}", klogging.Ansi.LRED)
            continue

    # Process changelogs
    changelogs = await glob.db.fetchall('SELECT * FROM changelog ORDER BY time DESC LIMIT 5')
    for log in changelogs:
        try:
            poster = await glob.db.fetch("SELECT name, id, country, priv FROM users WHERE id = %s", [log['poster']])
            if not poster:
                continue

            poster_badges = await glob.db.fetchall(
                "SELECT badge_id FROM user_badges WHERE userid = %s",
                (log['poster'],),
            )
            badges = []
            for user_badge in poster_badges:
                badge_id = user_badge["badge_id"]
                badge = await glob.db.fetch("SELECT * FROM badges WHERE id = %s", (badge_id,))
                if not badge:
                    continue
                    
                badge_styles = await glob.db.fetchall("SELECT * FROM badge_styles WHERE badge_id = %s", (badge_id,))
                badge = dict(badge)
                badge["styles"] = {style["type"]: style["value"] for style in badge_styles}
                badges.append(badge)
            
            badges.sort(key=lambda x: x['priority'], reverse=True)
            poster['badges'] = badges
            log['poster'] = poster
        except Exception as e:
            klogging.log(f"Error fetching changelog author: {e}", klogging.Ansi.LRED)
            # Don't return error, just skip this log entry
            continue

    # Most played beatmaps in the last 7 days
    try:
        most_played = await glob.db.fetchall(
            "SELECT s.map_md5, COUNT(*) as play_count, "
            "m.id, m.set_id, m.artist, m.title, m.creator, m.diff, m.mode "
            "FROM scores s "
            "JOIN maps m ON s.map_md5 = m.md5 "
            "WHERE s.play_time > NOW() - INTERVAL 7 DAY "
            "AND m.status IN (2, 3) "
            "GROUP BY s.map_md5 "
            "ORDER BY play_count DESC "
            "LIMIT 8"
        )
    except Exception:
        most_played = []

    # Recent registered users (for avatar stack)
    try:
        recent_users = await glob.db.fetchall(
            "SELECT id, name, country FROM users "
            "WHERE priv & 1 "
            "ORDER BY id DESC LIMIT 5"
        )
    except Exception:
        recent_users = []

    try:
        total_scores_row = await glob.db.fetch(
            "SELECT COUNT(*) as cnt FROM scores"
        )
        total_scores = total_scores_row['cnt'] if total_scores_row else 0
    except Exception:
        total_scores = 0

    # Determine flash messages based on global state (if not provided)
    if flash is None:
        if g.isDevEnv:
            flash = f"This Website is the Dev Environment. Please play on <a href='https://{glob.config.official_domain}'>our Official Server</a>"
            status = "success"
        elif g.maintenance:
            flash = "Website is currently under maintenance."
            status = "success"

    return await render_template(
        'home.html',
        unix_timestamp=unix_timestamp,
        changelogs=changelogs,
        rankedmaps=newly_ranked,
        doc=doc,
        dash_data=dash_data,
        globalNotice=g.globalNotice,
        flash=flash,
        status=status,
        most_played=most_played or [],
        recent_users=recent_users or [],
        total_scores=total_scores
    )

@frontend.route('/home/account/edit')
@error_catcher
async def home_account_edit():
    return redirect('/settings/profile')

@frontend.route('/settings')
@frontend.route('/settings/profile')
@error_catcher
@login_required
async def settings_profile():
    return await render_template('settings/profile.html', globalNotice=g.globalNotice)

@frontend.route('/settings/profile', methods=['POST'])
@error_catcher
@login_required
async def settings_profile_post():
    form = await request.form

    new_name = form.get('username', type=str)
    new_email = form.get('email', type=str)
    new_hue = form.get('hue', type=int)

    if new_name is None or new_email is None:
        return await flash('error', 'Invalid parameters.', 'home')

    old_name  = session['user_data']['name']
    old_email = session['user_data']['email']
    old_hue = session['user_data'].get('hue', 190)

    # no data has changed; deny post
    if new_name == old_name and new_email == old_email and new_hue == old_hue:
        return await flash('error', 'No changes have been made.', 'settings/profile')

    if new_name != old_name:
        if not session['user_data']['is_donator']:
            return await flash('error', 'Username changes are currently a supporter perk.', 'settings/profile')

        if not regexes.username.match(new_name):
            return await flash('error', 'Your new username syntax is invalid.', 'settings/profile')

        if '_' in new_name and ' ' in new_name:
            return await flash('error', 'Your new username may contain "_" or " ", but not both.', 'settings/profile')

        if new_name in glob.config.disallowed_names:
            return await flash('error', "Your new username isn't allowed; pick another.", 'settings/profile')

        if await glob.db.fetch('SELECT 1 FROM users WHERE name = %s', [new_name]):
            return await flash('error', 'Your new username already taken by another user.', 'settings/profile')

        safe_name = utils.get_safe_name(new_name)

        await glob.db.execute(
            'UPDATE users SET name = %s, safe_name = %s WHERE id = %s',
            [new_name, safe_name, session['user_data']['id']]
        )

    if new_email != old_email:
        if not regexes.email.match(new_email):
            return await flash('error', 'Your new email syntax is invalid.', 'settings/profile')

        if await glob.db.fetch('SELECT 1 FROM users WHERE email = %s', [new_email]):
            return await flash('error', 'Your new email already taken by another user.', 'settings/profile')

        await glob.db.execute(
            'UPDATE users SET email = %s WHERE id = %s',
            [new_email, session['user_data']['id']]
        )
        
    if new_hue is not None and 0 <= new_hue <= 360:
        await glob.db.execute(
            'INSERT INTO user_customisations (userid, hue) VALUES (%s, %s) ON DUPLICATE KEY UPDATE hue = %s',
            [session['user_data']['id'], new_hue, new_hue]
        )

    # Only require re-login if name or email changed
    if new_name != old_name or new_email != old_email:
        session.pop('authenticated', None)
        session.pop('user_data', None)
        return await flash('success', 'Your username/email have been changed! Please login again.', 'hinaDir/login')

    # Hue-only change: update session and stay on page
    if new_hue is not None and 0 <= new_hue <= 360:
        session['user_data']['hue'] = new_hue
        session.modified = True
    return await flash('success', 'Settings saved.', 'settings/profile')

@frontend.route('/settings/hue', methods=['POST'])
@login_required
async def settings_hue_post():
    """AJAX endpoint to update hue without logout."""
    form = await request.form
    new_hue = form.get('hue', type=int)

    if new_hue is None or new_hue < 0 or new_hue > 360:
        return {'status': 'error', 'message': 'Invalid hue value'}, 400

    await glob.db.execute(
        'INSERT INTO user_customisations (userid, hue) VALUES (%s, %s) '
        'ON DUPLICATE KEY UPDATE hue = %s',
        [session['user_data']['id'], new_hue, new_hue]
    )

    session['user_data']['hue'] = new_hue
    session.modified = True

    return {'status': 'success', 'hue': new_hue}, 200

@frontend.route('/settings/avatar')
@error_catcher
@login_required
async def settings_avatar():
    return await render_template('settings/avatar.html', globalNotice=g.globalNotice)

@frontend.route('/settings/avatar', methods=['POST'])
@error_catcher
@login_required
async def settings_avatar_post():
    MAX_IMAGE_SIZE = glob.config.max_image_size * 1024 * 1024
    if glob.config.seperate_data_path:
        AVATARS_PATH = './.data/b.py/avatars'
    else:
        AVATARS_PATH = f'{glob.config.path_to_gulag}.data/avatars'
        
    ALLOWED_EXTENSIONS = ['.jpeg', '.jpg', '.png']
    if session['user_data']['is_donator']:
        ALLOWED_EXTENSIONS.append('.gif')
        MAX_IMAGE_SIZE = glob.config.max_image_size_supporter * 1024 * 1024

    avatar = (await request.files).get('avatar')

    if avatar is None or not avatar.filename:
        return await flash('error', 'No image was selected!', 'settings/avatar')

    filename, file_extension = os.path.splitext(avatar.filename.lower())

    if file_extension not in ALLOWED_EXTENSIONS:
        if file_extension == '.gif':
            return await flash('error', 'Only donators can use .gif avatars!', 'settings/avatar')
        return await flash('error', 'The image you select must be either a .JPG, .JPEG, or .PNG file!', 'settings/avatar')

    # Read file bytes and check actual size (content_length may be None)
    avatar_data = await avatar.read()
    if len(avatar_data) > MAX_IMAGE_SIZE:
        msg = 'The image you selected is too large!'
        if not session['user_data']['is_donator']:
            msg += ' Become a donor to get double the size!'
        return await flash('error', msg, 'settings/avatar')

    save_filename = f'{session["user_data"]["id"]}{file_extension.lower()}'
    save_path = os.path.join(AVATARS_PATH, save_filename)
    temp_path = save_path + '.tmp'

    # Save new avatar to temp file first
    try:
        if file_extension.lower() != '.gif':
            pilavatar = Image.open(io.BytesIO(avatar_data))
            pilavatar = utils.crop_image(pilavatar)
            img_format = 'PNG' if file_extension.lower() == '.png' else 'JPEG'
            pilavatar.save(temp_path, format=img_format)
        else:
            with open(temp_path, "wb") as output_file:
                output_file.write(avatar_data)
    except Exception as e:
        if os.path.isfile(temp_path):
            os.remove(temp_path)
        klogging.log(f"Error saving avatar: {e}", klogging.Ansi.LRED)
        return await flash('error', 'Error saving avatar', 'settings/avatar')

    # Only delete old avatars after new one saved successfully
    for fx in ALLOWED_EXTENSIONS:
        old_path = os.path.join(AVATARS_PATH, f'{session["user_data"]["id"]}{fx}')
        if os.path.isfile(old_path) and old_path != temp_path:
            os.remove(old_path)

    os.rename(temp_path, save_path)

    return await flash('success', 'Your avatar has been successfully changed!', 'settings/avatar')

@frontend.route('/settings/custom')
@error_catcher
@login_required
async def settings_custom():
    profile_customizations = utils.has_profile_customizations(session['user_data']['id'])
    return await render_template('settings/custom.html', customizations=profile_customizations, globalNotice=g.globalNotice)

@frontend.route('/settings/custom', methods=['POST'])
@error_catcher
@login_required
async def settings_custom_post():
    files = await request.files
    banner = files.get('banner')
    background = files.get('background')
    ALLOWED_EXTENSIONS = ['.jpeg', '.jpg', '.png']
    if session['user_data']['is_donator']:
        ALLOWED_EXTENSIONS.append('.gif')

    if banner is None and background is None:
        return await flash_with_customizations('error', 'No image was selected!', 'settings/custom')

    if banner is not None and banner.filename:
        _, file_extension = os.path.splitext(banner.filename.lower())
        if file_extension not in ALLOWED_EXTENSIONS:
            if file_extension == '.gif':
                return await flash_with_customizations('error', 'Only donators can use .gif banners!', 'settings/custom')
            return await flash_with_customizations('error', 'The banner you select must be either a .JPG, .JPEG, or .PNG file!', 'settings/custom')

        banner_file_no_ext = Path('.data/banners') / f'{session["user_data"]["id"]}'
        save_path = f'{banner_file_no_ext}{file_extension}'
        temp_path = save_path + '.tmp'

        await banner.save(temp_path)
        try:
            await glob.db.execute(
                'INSERT INTO user_customisations (userid, has_banner) VALUES (%s, 1) '
                'ON DUPLICATE KEY UPDATE has_banner = 1',
                [session['user_data']['id']]
            )
        except Exception as e:
            if Path(temp_path).exists():
                Path(temp_path).unlink()
            return await flash_with_customizations('error', f'Error updating banner in database: {e}', 'settings/custom')

        # Remove old files only after successful save + DB update
        for ext in ALLOWED_EXTENSIONS:
            old = banner_file_no_ext.with_suffix(ext)
            if old.exists() and str(old) != temp_path:
                old.unlink()

        os.rename(temp_path, save_path)

    if background is not None and background.filename:
        _, file_extension = os.path.splitext(background.filename.lower())
        if file_extension not in ALLOWED_EXTENSIONS:
            if file_extension == '.gif':
                return await flash_with_customizations('error', 'Only donators can use .gif backgrounds!', 'settings/custom')
            return await flash_with_customizations('error', 'The background you select must be either a .JPG, .JPEG, or .PNG file!', 'settings/custom')

        background_file_no_ext = Path('.data/backgrounds') / f'{session["user_data"]["id"]}'
        save_path = f'{background_file_no_ext}{file_extension}'
        temp_path = save_path + '.tmp'

        await background.save(temp_path)
        try:
            await glob.db.execute(
                'INSERT INTO user_customisations (userid, has_background) VALUES (%s, 1) '
                'ON DUPLICATE KEY UPDATE has_background = 1',
                [session['user_data']['id']]
            )
        except Exception as e:
            if Path(temp_path).exists():
                Path(temp_path).unlink()
            return await flash_with_customizations('error', f'Error updating background in database: {e}', 'settings/custom')

        # Remove old files only after successful save + DB update
        for ext in ALLOWED_EXTENSIONS:
            old = background_file_no_ext.with_suffix(ext)
            if old.exists() and str(old) != temp_path:
                old.unlink()

        os.rename(temp_path, save_path)

    return await flash_with_customizations('success', 'Your customisation has been successfully changed!', 'settings/custom')

@frontend.route('/settings/password')
@error_catcher
@login_required
async def settings_password():
    return await render_template('settings/password.html', globalNotice=g.globalNotice)

@frontend.route('/settings/password', methods=["POST"])
@error_catcher
@login_required
async def settings_password_post():
    form = await request.form
    old_password = form.get('old_password')
    new_password = form.get('new_password')
    repeat_password = form.get('repeat_password')

    if new_password != repeat_password:
        return await flash('error', "Your new password doesn't match your repeated password!", 'settings/password')

    if old_password == new_password:
        return await flash('error', 'Your new password cannot be the same as your old password!', 'settings/password')

    if not 8 < len(new_password) <= 32:
        return await flash('error', 'Your new password must be 8-32 characters in length.', 'settings/password')

    if len(set(new_password)) <= 3:
        return await flash('error', 'Your new password must have more than 3 unique characters.', 'settings/password')

    if new_password.lower() in glob.config.disallowed_passwords:
        return await flash('error', 'Your new password was deemed too simple.', 'settings/password')

    # Cache and password info
    bcrypt_cache = glob.cache['bcrypt']
    
    user_row = await glob.db.fetch('SELECT pw_bcrypt FROM users WHERE id = %s', [session['user_data']['id']])
    if not user_row:
        return await flash('error', 'User not found.', 'hinaDir/login')
        
    pw_bcrypt = user_row['pw_bcrypt'].encode()
    pw_md5 = hashlib.md5(old_password.encode()).hexdigest().encode()

    # Check old password
    if pw_bcrypt in bcrypt_cache:
        if pw_md5 != bcrypt_cache[pw_bcrypt]:
            if glob.config.debug:
                klogging.log(f"{session['user_data']['name']}'s change pw failed - pw incorrect.", klogging.Ansi.LYELLOW)
            return await flash('error', 'Your old password is incorrect.', 'settings/password')
    else:
        if not bcrypt.checkpw(pw_md5, pw_bcrypt):
            if glob.config.debug:
                klogging.log(f"{session['user_data']['name']}'s change pw failed - pw incorrect.", klogging.Ansi.LYELLOW)
            return await flash('error', 'Your old password is incorrect.', 'settings/password')

    # Remove old from cache
    if pw_bcrypt in bcrypt_cache:
        del bcrypt_cache[pw_bcrypt]

    # Calculate new
    pw_md5 = hashlib.md5(new_password.encode()).hexdigest().encode()
    pw_bcrypt = bcrypt.hashpw(pw_md5, bcrypt.gensalt())

    # Update cache and DB
    bcrypt_cache[pw_bcrypt] = pw_md5
    await glob.db.execute(
        'UPDATE users SET pw_bcrypt = %s WHERE safe_name = %s',
        [pw_bcrypt, utils.get_safe_name(session['user_data']['name'])]
    )

    session.pop('authenticated', None)
    session.pop('user_data', None)
    return await flash('success', 'Your password has been changed! Please log in again.', 'hinaDir/login')

@frontend.route('/u/<id>')
@frontend.route('/user/<id>')
@frontend.route('/users/<id>')
@error_catcher
async def profile_select(id):
    mode = request.args.get('mode', 'std', type=str)
    mods = request.args.get('mods', 'vn', type=str)
    
    user_data = await glob.db.fetch(
        'SELECT users.name, users.safe_name, users.id, users.priv, users.country, user_customisations.hue '
        'FROM users '
        'LEFT JOIN user_customisations ON users.id = user_customisations.userid '
        'WHERE users.safe_name = %s OR users.id = %s LIMIT 1',
        [utils.get_safe_name(id), id]
    )

    if not user_data:
        return (await render_template('404.html'), 404)

    if mode not in VALID_MODES or mods not in VALID_MODS:
        return (await render_template('404.html'), 404)

    is_staff = 'authenticated' in session and session['user_data']['is_staff']
    if not (user_data['priv'] & Privileges.Normal or is_staff):
        return (await render_template('404.html'), 404)

    user_data['customisation'] = utils.has_profile_customizations(user_data['id'])
    
    g.Player = {
        "id": user_data['id'],
        "name": user_data['name'],
        "country": user_data['country'],
    }

    # Apply dev/maintenance flash if needed
    if g.isDevEnv:
        return await render_template('profile.html', user=user_data, mode=mode, mods=mods, globalNotice=g.globalNotice, 
                                   flash=f"This Website is the Dev Environment. Please play on <a href='https://{glob.config.official_domain}'>our Official Server</a>", status="success")
    if g.maintenance:
        return await render_template('profile.html', user=user_data, mode=mode, mods=mods, globalNotice=g.globalNotice, 
                                   flash="Website is currently under maintenance", status="success")
                                   
    return await render_template('profile.html', user=user_data, mode=mode, mods=mods, globalNotice=g.globalNotice)

@frontend.route('/leaderboard')
@frontend.route('/lb')
@frontend.route('/leaderboard/<mode>/<sort>/<mods>/')
@frontend.route('/leaderboard/<mode>/<sort>/<mods>/<view>')
@frontend.route('/leaderboard/<mode>/<sort>/<mods>/<view>/<season>')
@frontend.route('/lb/<mode>/<sort>/<mods>/')
@frontend.route('/lb/<mode>/<sort>/<mods>/<view>')
@frontend.route('/lb/<mode>/<sort>/<mods>/<view>/<season>')
@error_catcher
async def leaderboard(mode='std', sort='pp', mods='vn', view='alltime', season='0'):
    if g.isDevEnv:
        return await render_template('leaderboard.html', mode=mode, sort=sort, mods=mods, view=view, season=season, globalNotice=g.globalNotice, 
                                   flash=f"This Website is the Dev Environment. Please play on <a href='https://{glob.config.official_domain}'>our Official Server</a>", status="success")
    if g.maintenance:
        return await render_template('leaderboard.html', mode=mode, sort=sort, mods=mods, view=view, season=season, globalNotice=g.globalNotice,
                                   flash="Website is currently under maintenance", status="success")
    return await render_template('leaderboard.html', mode=mode, sort=sort, mods=mods, view=view, season=season, globalNotice=g.globalNotice)

@frontend.route('/clans')
@error_catcher
async def clans():
    if g.isDevEnv:
        return await render_template('clans.html', globalNotice=g.globalNotice, flash=f"This Website is the Dev Environment. Please play on <a href='https://{glob.config.official_domain}'>our Official Server</a>", status="success")
    if g.maintenance:
        return await render_template('clans.html', globalNotice=g.globalNotice, flash="Website is currently under maintenance", status="success")
    return await render_template('clans.html', globalNotice=g.globalNotice)

@frontend.route('/login')
@error_catcher
async def login():
    if 'authenticated' in session:
        return await flash('error', "You're already logged in!", 'home')
    
    if g.isDevEnv:
        return await render_template('login.html', globalNotice=g.globalNotice, flash=f"This Website is the Dev Environment. Please play on <a href='https://{glob.config.official_domain}'>our Official Server</a>", status="success")
    if g.maintenance:
        return await render_template('login.html', globalNotice=g.globalNotice, flash="Website is currently under maintenance", status="success")
        
    return await render_template('login.html', globalNotice=g.globalNotice)

@frontend.route('/login', methods=['POST'])
@error_catcher
async def login_post():
    if 'authenticated' in session:
        return await flash('error', "You're already logged in!", 'home')

    login_time = time.time_ns() if glob.config.debug else 0

    form = await request.form
    username = form.get('username', type=str)
    passwd_txt = form.get('password', type=str)

    if username is None or passwd_txt is None:
        return await flash('error', 'Invalid parameters.', 'home')

    user_info = await glob.db.fetch(
        'SELECT users.id, users.name, users.safe_name, users.email, users.priv, '
        'users.pw_bcrypt, users.silence_end, users.clan_id, users.donor_end, '
        'user_customisations.hue, '
        'clans.name AS clan_name, clans.tag AS clan_tag '
        'FROM users '
        'LEFT JOIN user_customisations ON users.id = user_customisations.userid '
        'LEFT JOIN clans ON users.clan_id = clans.id AND users.clan_id > 0 '
        'WHERE users.safe_name = %s',
        [utils.get_safe_name(username)]
    )
    
    badges = []
    if user_info and user_info['id']:
        user_badges = await glob.db.fetchall("SELECT badge_id FROM user_badges WHERE userid = %s", [user_info['id']])
        for user_badge in user_badges:
            badge = await glob.db.fetch("SELECT * FROM badges WHERE id = %s", [user_badge["badge_id"]])
            if badge:
                badge_styles = await glob.db.fetchall("SELECT * FROM badge_styles WHERE badge_id = %s", [user_badge["badge_id"]])
                badge = dict(badge)
                badge["styles"] = {style["type"]: style["value"] for style in badge_styles}
                badges.append(badge)
        badges.sort(key=lambda x: x['priority'], reverse=True)

    if not user_info or user_info['id'] == 1:
        if glob.config.debug:
            klogging.log(f"{username}'s login failed - account doesn't exist.", klogging.Ansi.LYELLOW)
        return await flash('error', 'Account does not exist.', 'hinaDir/login')

    bcrypt_cache = glob.cache['bcrypt']
    pw_bcrypt = user_info['pw_bcrypt'].encode()
    pw_md5 = hashlib.md5(passwd_txt.encode()).hexdigest().encode()

    if pw_bcrypt in bcrypt_cache:
        if pw_md5 != bcrypt_cache[pw_bcrypt]:
            if glob.config.debug:
                klogging.log(f"{username}'s login failed - pw incorrect.", klogging.Ansi.LYELLOW)
            return await flash('error', 'Password is incorrect.', 'hinaDir/login')
    else:
        if not bcrypt.checkpw(pw_md5, pw_bcrypt):
            if glob.config.debug:
                klogging.log(f"{username}'s login failed - pw incorrect.", klogging.Ansi.LYELLOW)
            return await flash('error', 'Password is incorrect.', 'hinaDir/login')
        bcrypt_cache[pw_bcrypt] = pw_md5

    if not user_info['priv'] & Privileges.Verified:
        if glob.config.debug:
            klogging.log(f"{username}'s login failed - not verified.", klogging.Ansi.LYELLOW)
        return await render_template('verify.html')

    if not user_info['priv'] & Privileges.Normal:
        if glob.config.debug:
            klogging.log(f"{username}'s login failed - banned.", klogging.Ansi.RED)
        return await flash('error', 'Your account is restricted. You are not allowed to log in.', 'hinaDir/login')

    if glob.config.debug:
        klogging.log(f"{username}'s login succeeded.", klogging.Ansi.LGREEN)

    session['authenticated'] = True
    session['user_data'] = {
        'id': user_info['id'],
        'name': user_info['name'],
        'safe_name': user_info['safe_name'],
        'badges': (badges or None),
        'email': user_info['email'],
        'priv': user_info['priv'],
        'silence_end': user_info['silence_end'],
        'is_staff': user_info['priv'] & Privileges.Staff != 0,
        'is_dev': user_info['priv'] & Privileges.Dangerous != 0,
        'is_donator': user_info['priv'] & Privileges.Donator != 0,
        'hue': user_info['hue'],
        'clan_id': user_info['clan_id'] or 0,
        'clan_name': user_info.get('clan_name') or None,
        'clan_tag': user_info.get('clan_tag') or None,
        'donor_end': user_info['donor_end'] or 0,
    }

    if glob.config.debug:
        login_time = (time.time_ns() - login_time) / 1e6
        klogging.log(f'Login took {login_time:.2f}ms!', klogging.Ansi.LYELLOW)
        
    g.Player = {
        "id": user_info['id'],
        "name": user_info['name'],
        "is_staff": user_info['priv'] & Privileges.Staff != 0,
        "is_dev": user_info['priv'] & Privileges.Dangerous != 0,
        "is_donator": user_info['priv'] & Privileges.Donator != 0,
        "priv": user_info['priv'],
    }
    return await home(status='success', flash=f'Hey, welcome back {username}!')

@frontend.route('/register')
@error_catcher
async def register():
    if 'authenticated' in session:
        return await flash('error', "You're already logged in.", 'home')

    if not glob.config.registration:
        return await flash('error', 'Registrations are currently disabled.', 'home')

    if g.isDevEnv:
        return await render_template('hinaDir/register.html', globalNotice=g.globalNotice, flash=f"This Website is the Dev Environment. Please play on <a href='https://{glob.config.official_domain}'>our Official Server</a>", status="success")
    if g.maintenance:
        return await render_template('hinaDir/register.html', globalNotice=g.globalNotice, flash="Website is currently under maintenance", status="success")
        
    return await render_template('hinaDir/register.html', globalNotice=g.globalNotice)

@frontend.route('/register', methods=['POST'])
@error_catcher
async def register_post():
    if 'authenticated' in session:
        return await flash('error', "You're already logged in.", 'home')

    if not glob.config.registration:
        return await flash('error', 'Registrations are currently disabled.', 'home')

    form = await request.form
    username = form.get('username', type=str)
    email = form.get('email', type=str)
    passwd_txt = form.get('password', type=str)

    if username is None or email is None or passwd_txt is None:
        return await flash('error', 'Invalid parameters.', 'home')

    if glob.config.hCaptcha_sitekey != 'changeme':
        captcha_data = form.get('h-captcha-response', type=str)
        if not captcha_data or not await utils.validate_captcha(captcha_data):
            return await flash('error', 'Captcha failed.', 'hinaDir/register')

    if not regexes.username.match(username):
        return await flash('error', 'Invalid username syntax.', 'hinaDir/register')

    if '_' in username and ' ' in username:
        return await flash('error', 'Username may contain "_" or " ", but not both.', 'hinaDir/register')

    if username in glob.config.disallowed_names:
        return await flash('error', 'Disallowed username; pick another.', 'hinaDir/register')

    if await glob.db.fetch('SELECT 1 FROM users WHERE name = %s', username):
        return await flash('error', 'Username already taken by another user.', 'hinaDir/register')

    if not regexes.email.match(email):
        return await flash('error', 'Invalid email syntax.', 'hinaDir/register')

    if await glob.db.fetch('SELECT 1 FROM users WHERE email = %s', email):
        return await flash('error', 'Email already taken by another user.', 'hinaDir/register')

    if not 8 <= len(passwd_txt) <= 32:
        return await flash('error', 'Password must be 8-32 characters in length.', 'hinaDir/register')

    if len(set(passwd_txt)) <= 3:
        return await flash('error', 'Password must have more than 3 unique characters.', 'hinaDir/register')

    if passwd_txt.lower() in glob.config.disallowed_passwords:
        return await flash('error', 'That password was deemed too simple.', 'hinaDir/register')

    # Hashing
    pw_md5 = hashlib.md5(passwd_txt.encode()).hexdigest().encode()
    pw_bcrypt = bcrypt.hashpw(pw_md5, bcrypt.gensalt())
    glob.cache['bcrypt'][pw_bcrypt] = pw_md5

    safe_name = utils.get_safe_name(username)

    # GeoIP
    country = 'xx'
    if request.headers and (ip := request.headers.get('X-Real-IP', type=str)):
        country = await utils.fetch_geoloc(ip)

    # DB Transaction
    async with glob.db.pool.acquire() as conn:
        async with conn.cursor() as db_cursor:
            await db_cursor.execute(
                'INSERT INTO users (name, safe_name, email, pw_bcrypt, country, creation_time, latest_activity) '
                'VALUES (%s, %s, %s, %s, %s, UNIX_TIMESTAMP(), UNIX_TIMESTAMP())',
                [username, safe_name, email, pw_bcrypt, country]
            )
            user_id = db_cursor.lastrowid

            # Batch insert stats
            modes = [0, 1, 2, 3, 4, 5, 6, 8] # vn!std, vn!taiko, vn!catch, vn!mania, rx!std, rx!taiko, rx!catch, ap!std
            stats_data = [(user_id, mode) for mode in modes]
            await db_cursor.executemany(
                'INSERT INTO stats (id, mode) VALUES (%s, %s)',
                stats_data
            )

    if glob.config.debug:
        klogging.log(f'{username} has registered - awaiting verification.', klogging.Ansi.LGREEN)

    return await render_template('verify.html')

@frontend.route('/logout')
@error_catcher
async def logout():
    if 'authenticated' not in session:
        return await flash('error', "You can't logout if you aren't logged in!", 'hinaDir/login')

    if glob.config.debug:
        klogging.log(f'{session["user_data"]["name"]} logged out.', klogging.Ansi.LGREEN)

    session.pop('authenticated', None)
    session.pop('user_data', None)

    return await flash('success', 'Successfully logged out!', 'hinaDir/login')

@frontend.route('/changelog')
@frontend.route('/changelog/<type>/<category>')
@error_catcher
async def changelog(type='frontend', category='all'):
    changelogs = await glob.db.fetchall("SELECT * FROM changelog ORDER BY 'time' DESC")
    for log in changelogs:
        poster = await glob.db.fetch("SELECT name, id, country, priv FROM users WHERE id = %s", [log['poster']])
        if not poster:
            continue
            
        poster_badges = await glob.db.fetchall("SELECT badge_id FROM user_badges WHERE userid = %s", (log['poster'],))
        badges = []
        for user_badge in poster_badges:
            badge_id = user_badge["badge_id"]
            badge = await glob.db.fetch("SELECT * FROM badges WHERE id = %s", (badge_id,))
            if not badge:
                continue
            badge_styles = await glob.db.fetchall("SELECT * FROM badge_styles WHERE badge_id = %s", (badge_id,))
            badge = dict(badge)
            badge["styles"] = {style["type"]: style["value"] for style in badge_styles}
            badges.append(badge)
            badges.sort(key=lambda x: x['priority'], reverse=True)
        
        poster['badges'] = badges
        log['poster'] = poster

    if g.isDevEnv:
        return await render_template('changelog.html', changelogs=changelogs, type=type, category=category, globalNotice=g.globalNotice, 
                                   flash=f"This Website is the Dev Environment. Please play on <a href='https://{glob.config.official_domain}'>our Official Server</a>", status="success")
    if g.maintenance:
        return await render_template('changelog.html', changelogs=changelogs, type=type, category=category, globalNotice=g.globalNotice, 
                                   flash="Website is currently under maintenance", status="success")
        
    return await render_template('changelog.html', changelogs=changelogs, type=type, category=category, globalNotice=g.globalNotice)

# social media redirections
@frontend.route('/github')
@frontend.route('/gh')
async def github_redirect():
    return redirect(glob.config.github)

@frontend.route('/discord')
async def discord_redirect():
    return redirect(glob.config.discord_server)

@frontend.route('/youtube')
@frontend.route('/yt')
async def youtube_redirect():
    return redirect(glob.config.youtube)

@frontend.route('/twitter')
async def twitter_redirect():
    return redirect(glob.config.twitter)

@frontend.route('/instagram')
@frontend.route('/ig')
async def instagram_redirect():
    return redirect(glob.config.instagram)

# profile customisation
BANNERS_PATH = Path.cwd() / '.data/banners'
BACKGROUND_PATH = Path.cwd() / '.data/backgrounds'

@frontend.route('/banners/<int:user_id>')
@error_catcher
async def get_profile_banner(user_id: int):
    for ext in ('jpg', 'jpeg', 'png', 'gif'):
        path = BANNERS_PATH / f'{user_id}.{ext}'
        if path.exists():
            return await send_file(path)
    return jsonify({'status': 404}), 404

@frontend.route('/backgrounds/<int:user_id>')
@error_catcher
async def get_profile_background(user_id: int):
    for ext in ('jpg', 'jpeg', 'png', 'gif'):
        path = BACKGROUND_PATH / f'{user_id}.{ext}'
        if path.exists():
            return await send_file(path)
    return jsonify({'status': 404}), 404