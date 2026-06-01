"""hinaDir: Auth-related page routes (forgot password, etc.)."""

from quart import Blueprint, g, render_template

from objects.utils import error_catcher

hina_auth = Blueprint('hina_auth', __name__)


@hina_auth.route('/forgot-password')
@error_catcher
async def forgot_password():
    """Render forgot password page."""
    return await render_template(
        'forgot_password.html',
        globalNotice=g.globalNotice,
    )
