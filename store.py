"""Storage backends for published mods.

Two interchangeable stores expose the same interface:

* ``LocalStore``    - files in ``mods_store/`` + an ``index.json`` (dev / no
  external deps; ephemeral on Render's free tier).
* ``SupabaseStore`` - a Supabase Storage bucket for the ``.rttmod`` files plus a
  Postgres table for metadata, so uploads are durable and downloadable by
  everyone.

``get_store()`` returns SupabaseStore when ``SUPABASE_URL`` and
``SUPABASE_SERVICE_KEY`` are set, otherwise LocalStore. Both return records with
the same shape:

    {id, name, author, version, description, sha256, size,
     uploaded_at, downloads, scan:[{level,code,message}, ...]}
"""

import os
import json
import datetime

try:
    import requests
except Exception:
    requests = None

BUCKET = os.environ.get('SUPABASE_BUCKET', 'mods')


def _now_iso():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + 'Z'


def _record(meta, sha256, size, findings, downloads=0, uploaded_at=None):
    return {
        'id': str(meta['id']),
        'name': str(meta.get('name', meta['id'])),
        'author': str(meta.get('author', 'unknown')),
        'version': str(meta.get('version', '')),
        'description': str(meta.get('description', '')),
        'sha256': sha256,
        'size': size,
        'uploaded_at': uploaded_at or _now_iso(),
        'downloads': downloads,
        'scan': [f.to_dict() for f in findings],
    }


# ---------------------------------------------------------------- local
class LocalStore:
    kind = 'local'

    def __init__(self, data_dir):
        self.dir = os.path.join(data_dir, 'mods_store')
        self.index = os.path.join(data_dir, 'index.json')
        os.makedirs(self.dir, exist_ok=True)

    def _load(self):
        try:
            with open(self.index, encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return {}

    def _save(self, idx):
        tmp = self.index + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(idx, f, indent=2)
        os.replace(tmp, self.index)

    def list_mods(self):
        idx = self._load()
        return sorted(idx.values(), key=lambda m: m.get('uploaded_at', ''),
                      reverse=True)

    def get_mod(self, mid):
        return self._load().get(mid)

    def save_mod(self, meta, data, findings):
        idx = self._load()
        mid = str(meta['id'])
        with open(os.path.join(self.dir, mid + '.rttmod'), 'wb') as out:
            out.write(data)
        prev = idx.get(mid, {})
        import hashlib
        rec = _record(meta, hashlib.sha256(data).hexdigest(), len(data),
                      findings, downloads=prev.get('downloads', 0))
        idx[mid] = rec
        self._save(idx)
        return rec

    def read_mod_bytes(self, mid):
        path = os.path.join(self.dir, mid + '.rttmod')
        if not os.path.isfile(path):
            return None
        with open(path, 'rb') as f:
            return f.read()

    def public_url(self, mid):
        return None   # served through the app

    def increment_download(self, mid):
        idx = self._load()
        if mid in idx:
            idx[mid]['downloads'] = idx[mid].get('downloads', 0) + 1
            self._save(idx)


# ------------------------------------------------------------- supabase
class SupabaseStore:
    kind = 'supabase'

    def __init__(self, url, key):
        if requests is None:
            raise RuntimeError('requests is required for SupabaseStore')
        self.url = url.rstrip('/')
        self.key = key
        self.rest = self.url + '/rest/v1'
        self.storage = self.url + '/storage/v1'

    def _h(self, extra=None):
        h = {'apikey': self.key, 'Authorization': 'Bearer ' + self.key}
        if extra:
            h.update(extra)
        return h

    def _obj_path(self, mid):
        return '%s/object/%s/%s.rttmod' % (self.storage, BUCKET, mid)

    def list_mods(self):
        r = requests.get(self.rest + '/mods',
                         headers=self._h(),
                         params={'select': '*', 'order': 'uploaded_at.desc'},
                         timeout=15)
        r.raise_for_status()
        return r.json()

    def get_mod(self, mid):
        r = requests.get(self.rest + '/mods', headers=self._h(),
                         params={'select': '*', 'id': 'eq.' + mid},
                         timeout=15)
        r.raise_for_status()
        rows = r.json()
        return rows[0] if rows else None

    def save_mod(self, meta, data, findings):
        import hashlib
        mid = str(meta['id'])
        # 1) upload the file (upsert)
        up = requests.post(
            self._obj_path(mid), headers=self._h({
                'Content-Type': 'text/plain; charset=utf-8',
                'x-upsert': 'true'}),
            data=data, timeout=30)
        up.raise_for_status()
        # 2) upsert the metadata row, preserving any existing download count
        prev = self.get_mod(mid) or {}
        rec = _record(meta, hashlib.sha256(data).hexdigest(), len(data),
                      findings, downloads=prev.get('downloads', 0))
        r = requests.post(
            self.rest + '/mods',
            headers=self._h({'Content-Type': 'application/json',
                             'Prefer': 'resolution=merge-duplicates'}),
            data=json.dumps(rec), timeout=15)
        r.raise_for_status()
        return rec

    def read_mod_bytes(self, mid):
        r = requests.get(self._obj_path(mid), headers=self._h(), timeout=30)
        if r.status_code != 200:
            return None
        return r.content

    def public_url(self, mid):
        # bucket is public -> a direct, CDN-friendly download link
        return '%s/object/public/%s/%s.rttmod' % (self.storage, BUCKET, mid)

    def increment_download(self, mid):
        cur = self.get_mod(mid)
        if not cur:
            return
        try:
            requests.patch(
                self.rest + '/mods', headers=self._h({
                    'Content-Type': 'application/json'}),
                params={'id': 'eq.' + mid},
                data=json.dumps({'downloads': cur.get('downloads', 0) + 1}),
                timeout=10)
        except Exception:
            pass


def get_store(data_dir):
    url = os.environ.get('SUPABASE_URL', '').strip()
    key = os.environ.get('SUPABASE_SERVICE_KEY', '').strip()
    if url and key and requests is not None:
        try:
            return SupabaseStore(url, key)
        except Exception as e:
            print('SupabaseStore unavailable, falling back to local:', e)
    return LocalStore(data_dir)
