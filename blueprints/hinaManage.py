# -*- coding: utf-8 -*-

"""
HinaManage Blueprint
Modular beatmap management system for KawaWeb v2
Handles beatmap search, download, and management functionality
"""

__all__ = ()

import asyncio
from typing import Dict, Any, Optional
from quart import Blueprint, render_template, request, jsonify, session

from objects import glob
from objects.utils import flash, error_catcher, klogging
from objects.privileges import Privileges

# Import our modular components
from blueprints.hinaManage_modules import beatmaps, api_handlers, utils

# Create the blueprint
hinaManage = Blueprint('hinaManage', __name__)


def login_required(func):
    """Decorator to require user login"""
    from functools import wraps
    
    @wraps(func)
    async def wrapper(*args, **kwargs):
        if not session or not session.get('authenticated'):
            return await flash('error', 'You must be logged in to access that page.', 'login')
        return await func(*args, **kwargs)
    return wrapper


@hinaManage.route('/')
@hinaManage.route('/beatmaps')
@error_catcher
async def beatmaps_home():
    """
    Main beatmaps page - accessible to all users
    """
    try:
        # Get global notice if it exists
        globalNotice = None
        try:
            if glob.sys.get('globalNotice') and glob.sys['globalNotice'] != "":
                globalNotice = glob.sys['globalNotice']
        except:
            pass
        
        # Check if this is a dev environment
        dev_flash = None
        try:
            if glob.sys.get('isDevEnv') == "True":
                dev_flash = f"This Website is the Dev Environment and should not be used for active play, please play on <a href='https://{glob.config.official_domain}'>our Official Server</a>"
        except:
            pass
        
        # Get hello world data from backend to test connectivity
        hello_data = await beatmaps.get_hello_world()
        
        return await render_template(
            'beatmaps_hina.html',
            globalNotice=globalNotice,
            flash=dev_flash,
            status="success" if dev_flash else None,
            hello_data=hello_data
        )
        
    except Exception as e:
        klogging.log(f"Error loading beatmaps page: {e}", klogging.Ansi.LRED)
        # Return a simple error page instead of redirecting to home
        return await render_template(
            'beatmaps_hina.html',
            globalNotice=None,
            flash='Failed to load beatmaps page. Please try again later.',
            status='error',
            hello_data={"status": "error", "message": str(e)}
        )


@hinaManage.route('/api/hello')
@error_catcher
async def api_hello():
    """
    API endpoint to test backend connectivity
    Returns JSON hello world response
    """
    try:
        hello_data = await beatmaps.get_hello_world()
        system_status = utils.get_system_status()
        
        response_data = {
            **hello_data,
            "system": system_status,
            "timestamp": asyncio.get_event_loop().time()
        }
        
        return jsonify(response_data), 200
        
    except Exception as e:
        klogging.log(f"Error in hello API: {e}", klogging.Ansi.LRED)
        return jsonify({
            "status": "error",
            "message": "Hello API failed",
            "error": str(e)
        }), 500


@hinaManage.route('/api/search')
@error_catcher
async def api_search():
    """
    API endpoint for beatmap search with dual API support
    """
    try:
        query = request.args.get('q', '').strip()
        limit = min(int(request.args.get('limit', 50)), 100)

        # Additional search parameters
        status = request.args.get('status', '')
        mode = request.args.get('mode', '')
        genre = request.args.get('genre', '')
        language = request.args.get('language', '')
        sort = request.args.get('sort', '')
        cursor = request.args.get('cursor', '')

        if not query:
            return jsonify({
                "success": False,
                "status": "error",
                "message": "Search query is required"
            }), 400

        # Sanitize the query
        clean_query = utils.sanitize_search_query(query)
        if not clean_query:
            return jsonify({
                "success": False,
                "status": "error",
                "message": "Invalid search query"
            }), 400


        # Build search parameters
        search_params = {}
        if status:
            search_params['status'] = status
        if mode:
            search_params['mode'] = mode
        if genre:
            search_params['genre'] = genre
        if language:
            search_params['language'] = language
        if sort:
            search_params['sort'] = sort
        if cursor:
            search_params['cursor_string'] = cursor

        # Perform search
        search_results = await beatmaps.search_beatmaps(
            clean_query,
            limit=limit,
            **search_params
        )

        return jsonify(search_results), 200

    except Exception as e:
        klogging.log(f"Error in search API: {e}", klogging.Ansi.LRED)
        return jsonify({
            "success": False,
            "status": "error",
            "message": "Search API failed",
            "error": str(e)
        }), 500


@hinaManage.route('/api/download/<int:beatmapset_id>')
@login_required
@error_catcher
async def api_download(beatmapset_id: int):
    """
    API endpoint for beatmapset download
    Requires user login
    """
    try:
        # Validate beatmapset ID
        valid_id = utils.validate_beatmap_id(beatmapset_id)
        if not valid_id:
            return jsonify({
                "success": False,
                "status": "error",
                "message": "Invalid beatmapset ID"
            }), 400

        # Get additional parameters
        no_video = request.args.get('no_video', '').lower() == 'true'

        # Attempt download
        download_result = await beatmaps.download_beatmap(valid_id, no_video)

        return jsonify(download_result), 200

    except Exception as e:
        klogging.log(f"Error in download API: {e}", klogging.Ansi.LRED)
        return jsonify({
            "success": False,
            "status": "error",
            "message": "Download API failed",
            "error": str(e)
        }), 500


@hinaManage.route('/api/beatmapset/<int:beatmapset_id>')
@error_catcher
async def api_beatmapset_info(beatmapset_id: int):
    """
    API endpoint to get detailed beatmapset information
    """
    try:
        # Validate beatmapset ID
        valid_id = utils.validate_beatmap_id(beatmapset_id)
        if not valid_id:
            return jsonify({
                "success": False,
                "status": "error",
                "message": "Invalid beatmapset ID"
            }), 400

        # Get beatmapset info
        beatmapset_result = await beatmaps.get_beatmapset(valid_id)

        return jsonify(beatmapset_result), 200

    except Exception as e:
        klogging.log(f"Error in beatmapset info API: {e}", klogging.Ansi.LRED)
        return jsonify({
            "success": False,
            "status": "error",
            "message": "Beatmapset info API failed",
            "error": str(e)
        }), 500


@hinaManage.route('/api/status')
@error_catcher
async def api_status():
    """
    API endpoint to get system status including both API sources
    """
    try:
        system_status = utils.get_system_status()

        # Test API connection
        from .hinaManage_modules.osu_api_v2 import osu_api

        osu_test = await osu_api.test_connection()

        response_data = {
            "status": "success",
            "system": system_status,
            "api_sources": {
                "osu": osu_test,
                "catboy": {
                    "status": "wip",
                    "message": "Catboy mirror integration is work in progress",
                    "api_responsive": False,
                    "service_url": "https://catboy.best"
                }
            },
            "timestamp": asyncio.get_event_loop().time()
        }

        return jsonify(response_data), 200

    except Exception as e:
        klogging.log(f"Error in status API: {e}", klogging.Ansi.LRED)
        return jsonify({
            "status": "error",
            "message": "Status API failed",
            "error": str(e)
        }), 500


# Admin-only routes
@hinaManage.route('/admin')
@hinaManage.route('/admin/dashboard')
@login_required
@error_catcher
async def admin_dashboard():
    """
    Admin dashboard for beatmap management
    Requires staff privileges
    """
    try:
        # Check if user is staff
        if not session.get('user_data', {}).get('is_staff', False):
            return await flash('error', 'You have insufficient privileges.', 'home')
        
        # Get system status for admin view
        system_status = utils.get_system_status()
        api_status = await api_handlers.test_api_connection()
        
        return await render_template(
            'admin/beatmaps_admin.html',
            system_status=system_status,
            api_status=api_status
        )
        
    except Exception as e:
        klogging.log(f"Error loading admin dashboard: {e}", klogging.Ansi.LRED)
        return await flash('error', 'Failed to load admin dashboard.', 'admin')


# Error handlers for this blueprint
@hinaManage.errorhandler(404)
async def not_found(error):
    """Handle 404 errors within this blueprint"""
    return await flash('error', 'Page not found.', 'home')


@hinaManage.errorhandler(500)
async def internal_error(error):
    """Handle 500 errors within this blueprint"""
    klogging.log(f"Internal error in hinaManage: {error}", klogging.Ansi.LRED)
    return await flash('error', 'Internal server error.', 'home')
