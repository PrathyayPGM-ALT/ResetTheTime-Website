"""Reset The Time - community mod portal.

Upload a `.rttmod`, it gets scanned (structure, static-safety allowlist,
profanity, and optional VirusTotal), and only clean mods are published for
download. The game's Mods tab links here.

Run locally:   python app.py
On Render:      gunicorn app:app   (see render.yaml)
"""

import os
import re
from io import BytesIO

from flask import (Flask, request, render_template, redirect, url_for,
                   send_file, abort, jsonify)

import scanner
import store as store_mod

BASE = os.path.dirname(os.path.abspath(__file__))
# DATA_DIR is the local-fallback location (used when Supabase isn't configured).
DATA_DIR = os.environ.get('DATA_DIR', BASE)
# Durable when SUPABASE_URL + SUPABASE_SERVICE_KEY are set; local otherwise.
store = store_mod.get_store(DATA_DIR)

# Game builds (Windows .exe, macOS .app zip, ...) dropped in here are served
# straight from the site. Anything in this folder shows up on /download.
BUILDS_DIR = os.environ.get('BUILDS_DIR', os.path.join(BASE, 'builds'))
os.makedirs(BUILDS_DIR, exist_ok=True)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = scanner.MAX_BYTES + 4096


# Fallback links used when no local build file is present for a platform.
GAME_DOWNLOAD_URL = os.environ.get(
    'GAME_DOWNLOAD_URL',
    'https://github.com/PrathyayPGM-ALT/ResetTheTime/releases/latest')
GAME_DOWNLOAD_URL_MAC = os.environ.get('GAME_DOWNLOAD_URL_MAC', '')


def _fmt_size(n):
    for unit in ('B', 'KB', 'MB', 'GB'):
        if n < 1024 or unit == 'GB':
            return '%.0f %s' % (n, unit) if unit == 'B' else '%.1f %s' % (n, unit)
        n /= 1024.0


def _platform_for(name):
    low = name.lower()
    if low.endswith('.exe') or 'win' in low:
        return 'Windows'
    if low.endswith(('.zip', '.dmg', '.app')) or 'mac' in low or 'osx' in low:
        return 'macOS'
    if low.endswith(('.appimage', '.tar.gz')) or 'linux' in low:
        return 'Linux'
    return 'Download'


def list_builds():
    """Local build files first, then external-link fallbacks per platform."""
    builds = []
    try:
        names = sorted(os.listdir(BUILDS_DIR))
    except Exception:
        names = []
    for name in names:
        path = os.path.join(BUILDS_DIR, name)
        if name.startswith('.') or not os.path.isfile(path):
            continue
        builds.append({
            'platform': _platform_for(name),
            'label': name,
            'href': url_for('serve_build', filename=name),
            'size': _fmt_size(os.path.getsize(path)),
            'external': False,
        })
    present = {b['platform'] for b in builds}
    if 'Windows' not in present:
        builds.append({'platform': 'Windows', 'label': 'ResetTheTime.exe',
                       'href': GAME_DOWNLOAD_URL, 'size': None,
                       'external': True})
    if 'macOS' not in present and GAME_DOWNLOAD_URL_MAC:
        builds.append({'platform': 'macOS', 'label': 'ResetTheTime (.app zip)',
                       'href': GAME_DOWNLOAD_URL_MAC, 'size': None,
                       'external': True})
    return builds


@app.context_processor
def inject_globals():
    return {'allowed': ', '.join(sorted(scanner.ALLOWED_IMPORTS)),
            'game_download_url': GAME_DOWNLOAD_URL}


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/download')
def game_download():
    return render_template('download.html', builds=list_builds())


@app.route('/builds/<path:filename>')
def serve_build(filename):
    # send_from_directory guards against path traversal.
    from flask import send_from_directory
    return send_from_directory(BUILDS_DIR, filename, as_attachment=True)


@app.route('/mods')
def mods_hub():
    try:
        mods = store.list_mods()
    except Exception as e:
        print('list_mods failed:', e)
        mods = []
    return render_template('mods.html', mods=mods)


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'GET':
        return render_template('upload.html', report=None)

    f = request.files.get('modfile')
    if not f or not f.filename:
        return render_template('upload.html',
                               report={'error': 'No file selected.'})
    data = f.read()
    result = scanner.scan_bytes(data, f.filename)

    if not result.ok:
        # rejected -- show the report, store nothing
        return render_template('upload.html', report=result.to_dict(),
                               filename=f.filename)

    try:
        rec = store.save_mod(result.meta, data, result.findings)
    except Exception as e:
        print('save_mod failed:', e)
        return render_template(
            'upload.html', filename=f.filename,
            report={'error': 'Passed scanning, but saving failed: %s' % e})
    return redirect(url_for('mod_page', mod_id=rec['id']))


@app.route('/mod/<mod_id>')
def mod_page(mod_id):
    mod = store.get_mod(mod_id)
    if not mod:
        abort(404)
    return render_template('mod.html', mod=mod)


@app.route('/mod/<mod_id>/download')
def download_mod(mod_id):
    if not re.match(r'^[a-z0-9_]{2,40}$', mod_id):
        abort(400)
    mod = store.get_mod(mod_id)
    if not mod:
        abort(404)
    store.increment_download(mod_id)
    pub = store.public_url(mod_id)
    if pub:
        return redirect(pub)
    data = store.read_mod_bytes(mod_id)
    if data is None:
        abort(404)
    return send_file(BytesIO(data), as_attachment=True,
                     download_name=mod_id + '.rttmod', mimetype='text/plain')


@app.route('/api/mods')
def api_mods():
    """Machine-readable catalogue the game could pull to list downloads."""
    try:
        rows = store.list_mods()
    except Exception as e:
        print('list_mods failed:', e)
        rows = []
    mods = [{
        'id': m['id'], 'name': m['name'], 'author': m['author'],
        'version': m['version'], 'description': m['description'],
        'sha256': m['sha256'], 'size': m['size'],
        'downloads': m.get('downloads', 0),
        'download_url': url_for('download_mod', mod_id=m['id'], _external=True),
    } for m in rows]
    mods.sort(key=lambda m: m['name'].lower())
    return jsonify({'mods': mods})


@app.route('/healthz')
def healthz():
    return {'status': 'ok'}


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
