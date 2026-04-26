"""hinaDir: Hall of Fame — all-time legends podium + ranked list (mode/sort/country)."""

from quart import Blueprint, g, render_template

from objects.utils import error_catcher

hina_hall_of_fame = Blueprint('hina_hall_of_fame', __name__)


@hina_hall_of_fame.route('/hall-of-fame')
@error_catcher
async def hall_of_fame():
    return await render_template('hall_of_fame.html', globalNotice=g.globalNotice)
