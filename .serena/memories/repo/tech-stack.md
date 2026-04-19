# Tech Stack

- **Backend**: Python / Flask (not Django - uses blueprints pattern)
- **Frontend**: Vue.js 2 with Jinja2 templates
- **CSS**: Bulma framework, custom SCSS/CSS
- **TypeScript**: Minimal - only in `static/hinaDir/` (compiled TS for specific features)
- **Database**: Likely MySQL/MariaDB (osu! private server ecosystem)
- **Deployment**: Docker + Nginx

## Project Structure
- `main.py` - Flask app entry point
- `blueprints/` - Flask blueprints (admin, frontend, hinaDir)
- `templates/` - Jinja2 HTML templates
- `static/` - CSS, JS, images, fonts
- `objects/` - Core Python objects (glob, privileges, utils)
