"""hinaDir: PP Records + Most Played page routes."""

from quart import Blueprint, g, render_template

from objects.utils import error_catcher

hina_pp_records = Blueprint('hina_pp_records', __name__)


@hina_pp_records.route('/records')
@error_catcher
async def pp_records():
    return await render_template('pp_records.html', globalNotice=g.globalNotice)


@hina_pp_records.route('/most-played')
@error_catcher
async def most_played():
    return await render_template('most_played.html', globalNotice=g.globalNotice)
