"""hinaDir: PP Records page route."""

from quart import Blueprint, g, render_template

from objects.utils import error_catcher

hina_pp_records = Blueprint('hina_pp_records', __name__)


@hina_pp_records.route('/records')
@error_catcher
async def pp_records():
    return await render_template('pp_records.html', globalNotice=g.globalNotice)
