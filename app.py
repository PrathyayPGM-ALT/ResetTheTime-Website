"""Reset The Time - community mod portal.

Upload a `.rttmod`, it gets scanned (structure, static-safety allowlist,
profanity, and optional VirusTotal), and only clean mods are published for
download. The game's Mods tab links here.

Run locally:   python app.py
On Render:      gunicorn app:app   (see render.yaml)
"""

import os
import json
import re
import datetime

from flask import (Flask, request, render_template, redirect, url_for,
                   send_file, abort, jsonify)

import scanner

BASE = os.path.dirname(os.path.abspath(__file__))
# DATA_DIR can point at a Render persistent disk so uploads survive restarts.
DATA_DIR = os.environ.get('DATA_DIR', BASE)
STORE = os.path.join(DATA_DIR, 'mods_store')      # published .rttmod files
INDEX = os.path.join(DATA_DIR, 'index.json')
os.makedirs(STORE, exist_ok=True)

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


def load_index():
    try:
        with open(INDEX, encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


def save_index(idx):
    tmp = INDEX + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(idx, f, indent=2)
    os.replace(tmp, INDEX)


def now_iso():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + 'Z'


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
    idx = load_index()
    mods = sorted(idx.values(), key=lambda m: m.get('uploaded_at', ''),
                  reverse=True)
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

    meta = result.meta
    mid = str(meta['id'])
    idx = load_index()
    path = os.path.join(STORE, mid + '.rttmod')
    with open(path, 'wb') as out:
        out.write(data)

    record = idx.get(mid, {})
    record.update({
        'id': mid,
        'name': str(meta.get('name', mid)),
        'author': str(meta.get('author', 'unknown')),
        'version': str(meta.get('version', '')),
        'description': str(meta.get('description', '')),
        'sha256': result.sha256,
        'size': len(data),
        'uploaded_at': now_iso(),
        'downloads': record.get('downloads', 0),
        'scan': [x.to_dict() for x in result.findings],
    })
    idx[mid] = record
    save_index(idx)
    return redirect(url_for('mod_page', mod_id=mid))


@app.route('/mod/<mod_id>')
def mod_page(mod_id):
    idx = load_index()
    mod = idx.get(mod_id)
    if not mod:
        abort(404)
    return render_template('mod.html', mod=mod)


@app.route('/mod/<mod_id>/download')
def download_mod(mod_id):
    if not re.match(r'^[a-z0-9_]{2,40}$', mod_id):
        abort(400)
    idx = load_index()
    mod = idx.get(mod_id)
    path = os.path.join(STORE, mod_id + '.rttmod')
    if not mod or not os.path.isfile(path):
        abort(404)
    mod['downloads'] = mod.get('downloads', 0) + 1
    save_index(idx)
    return send_file(path, as_attachment=True,
                     download_name=mod_id + '.rttmod',
                     mimetype='text/plain')


@app.route('/api/mods')
def api_mods():
    """Machine-readable catalogue the game could pull to list downloads."""
    idx = load_index()
    mods = [{
        'id': m['id'], 'name': m['name'], 'author': m['author'],
        'version': m['version'], 'description': m['description'],
        'sha256': m['sha256'], 'size': m['size'],
        'downloads': m.get('downloads', 0),
        'download_url': url_for('download_mod', mod_id=m['id'], _external=True),
    } for m in idx.values()]
    mods.sort(key=lambda m: m['name'].lower())
    return jsonify({'mods': mods})


@app.route('/healthz')
def healthz():
    return {'status': 'ok'}


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
