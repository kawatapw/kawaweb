"""hinaDir: Auth-related page routes (forgot password, etc.)."""

from quart import Blueprint, render_template, g

from objects.utils import error_catcher

hina_auth = Blueprint('hina_auth', __name__)


@hina_auth.route('/forgot-password')
@error_catcher
async def forgot_password():
    return await render_template(
        'hinaDir/forgot_password.html',
        globalNotice=g.globalNotice,
    )
