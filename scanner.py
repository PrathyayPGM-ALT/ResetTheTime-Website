"""Mod scanning pipeline for the Reset The Time mod portal.

A `.rttmod` is executable Python that players run on their own machines, so an
upload must clear several gates before it's ever offered for download:

1. structural     - right extension, sane size, valid UTF-8, parses as Python
2. manifest       - has a well-formed MOD dict + an apply() function
3. static safety  - AST allowlist: no dangerous imports / calls / dunder tricks
4. content        - profanity / inappropriate text in code or metadata
5. antivirus      - VirusTotal hash lookup (optional, needs VT_API_KEY)

Any BLOCK-level finding rejects the upload. WARN findings are surfaced but
allowed. Static analysis is the primary defense; VirusTotal can only *reject*
on positive detections, never block a merely-unknown file.
"""

import ast
import re
import hashlib
import os

try:
    import requests
except Exception:            # requests is optional at import time
    requests = None


MAX_BYTES = 256 * 1024
ID_RE = re.compile(r'^[a-z0-9_]{2,40}$')
REQUIRED_META = ('id', 'name', 'version', 'author', 'description')

# Modules a mod may import. Everything else is blocked -- these are pure/,
# rendering-only helpers with no file, network, process or reflection access.
ALLOWED_IMPORTS = {
    'math', 'random', 'colorsys', 'itertools', 'functools', 'collections',
    'statistics', 'cmath', 'decimal', 'fractions', 'bisect', 'heapq',
    'pygame', 'numpy',
}

# Names that enable code execution / sandbox escape / IO.
BANNED_CALLS = {
    'eval', 'exec', 'compile', '__import__', 'open', 'input', 'breakpoint',
    'globals', 'locals', 'vars', 'getattr', 'setattr', 'delattr',
    'memoryview', 'exit', 'quit', 'help',
}
# Dunder attributes used for reflection-based escapes.
BANNED_ATTRS = {
    '__globals__', '__builtins__', '__subclasses__', '__bases__', '__mro__',
    '__class__', '__code__', '__closure__', '__dict__', '__loader__',
    '__import__', '__getattribute__', '__reduce__', '__reduce_ex__',
    '__base__', '__init_subclass__',
}

# Deliberately conservative. Extend as needed.
PROFANITY = {
    'fuck', 'shit', 'bitch', 'cunt', 'nigger', 'nigga', 'faggot', 'fag',
    'rape', 'rapist', 'whore', 'slut', 'retard', 'kike', 'spic', 'chink',
    'porn', 'pornhub', 'nazi', 'heil', 'molest', 'pedo', 'pedophile',
}
_WORD_RE = re.compile(r'[a-z]+')


class Finding:
    def __init__(self, level, code, message):
        self.level = level        # 'block' or 'warn'
        self.code = code
        self.message = message

    def to_dict(self):
        return {'level': self.level, 'code': self.code, 'message': self.message}


class ScanResult:
    def __init__(self):
        self.findings = []
        self.meta = None
        self.sha256 = None

    def add(self, level, code, message):
        self.findings.append(Finding(level, code, message))

    @property
    def blocked(self):
        return any(f.level == 'block' for f in self.findings)

    @property
    def ok(self):
        return not self.blocked and self.meta is not None

    def to_dict(self):
        return {
            'ok': self.ok,
            'blocked': self.blocked,
            'sha256': self.sha256,
            'meta': self.meta,
            'findings': [f.to_dict() for f in self.findings],
        }


# --------------------------------------------------------------------------
def _extract_meta(tree):
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id == 'MOD':
                    try:
                        val = ast.literal_eval(node.value)
                    except Exception:
                        return None, 'MOD must be a plain literal dict'
                    if not isinstance(val, dict):
                        return None, 'MOD must be a dict'
                    return val, None
    return None, 'no MOD metadata dict found'


def _has_apply(tree):
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == 'apply':
            return True
    return False


def _static_safety(tree, res):
    for node in ast.walk(tree):
        # imports
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split('.')[0]
                if root not in ALLOWED_IMPORTS:
                    res.add('block', 'import',
                            "imports '%s' (not on the allowlist)" % alias.name)
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or '').split('.')[0]
            if node.names and node.names[0].name == '*':
                res.add('block', 'import-star', 'uses "from ... import *"')
            if root and root not in ALLOWED_IMPORTS:
                res.add('block', 'import',
                        "imports from '%s' (not on the allowlist)" % node.module)
        # calls to banned builtins
        elif isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name) and fn.id in BANNED_CALLS:
                res.add('block', 'call', "calls '%s()'" % fn.id)
        # banned attribute access (reflection escapes)
        elif isinstance(node, ast.Attribute):
            if node.attr in BANNED_ATTRS:
                res.add('block', 'attr',
                        "accesses '%s' (reflection/escape)" % node.attr)
        # names ending with dunder used directly
        elif isinstance(node, ast.Name):
            if node.id in BANNED_ATTRS:
                res.add('block', 'name', "references '%s'" % node.id)


def _content_filter(text, res, where):
    words = set(_WORD_RE.findall(text.lower()))
    hits = sorted(words & PROFANITY)
    if hits:
        res.add('block', 'content',
                'inappropriate language in %s: %s' % (where, ', '.join(hits)))


def virustotal_scan(data, res):
    """Optional VirusTotal hash lookup. Only rejects on positive detections."""
    key = os.environ.get('VT_API_KEY', '').strip()
    if not key:
        res.add('warn', 'vt-skip', 'VirusTotal not configured (no VT_API_KEY)')
        return
    if requests is None:
        res.add('warn', 'vt-skip', 'requests library unavailable')
        return
    sha = res.sha256
    try:
        r = requests.get('https://www.virustotal.com/api/v3/files/' + sha,
                         headers={'x-apikey': key}, timeout=15)
        if r.status_code == 200:
            stats = (r.json().get('data', {}).get('attributes', {})
                     .get('last_analysis_stats', {}))
            mal = int(stats.get('malicious', 0))
            susp = int(stats.get('suspicious', 0))
            if mal + susp > 0:
                res.add('block', 'vt',
                        'VirusTotal: %d malicious / %d suspicious detections'
                        % (mal, susp))
            else:
                res.add('warn', 'vt-clean', 'VirusTotal: no detections')
        elif r.status_code == 404:
            res.add('warn', 'vt-unknown',
                    'VirusTotal has not seen this file (relying on static scan)')
        else:
            res.add('warn', 'vt-error',
                    'VirusTotal lookup returned HTTP %d' % r.status_code)
    except Exception as e:
        res.add('warn', 'vt-error', 'VirusTotal lookup failed: %s' % e)


def scan_bytes(data, filename):
    """Run the whole pipeline over raw uploaded bytes. Returns a ScanResult."""
    res = ScanResult()
    res.sha256 = hashlib.sha256(data).hexdigest()

    if not filename.lower().endswith('.rttmod'):
        res.add('block', 'ext', 'file must have a .rttmod extension')
        return res
    if len(data) == 0:
        res.add('block', 'empty', 'file is empty')
        return res
    if len(data) > MAX_BYTES:
        res.add('block', 'size', 'file exceeds %d KB' % (MAX_BYTES // 1024))
        return res
    try:
        src = data.decode('utf-8')
    except UnicodeDecodeError:
        res.add('block', 'encoding', 'file is not valid UTF-8 text')
        return res
    try:
        tree = ast.parse(src)
    except SyntaxError as e:
        res.add('block', 'syntax', 'not valid Python: %s' % e.msg)
        return res

    meta, err = _extract_meta(tree)
    if err:
        res.add('block', 'manifest', err)
    else:
        missing = [k for k in REQUIRED_META if not str(meta.get(k, '')).strip()]
        if missing:
            res.add('block', 'manifest',
                    'MOD is missing: %s' % ', '.join(missing))
        elif not ID_RE.match(str(meta.get('id', ''))):
            res.add('block', 'manifest',
                    "MOD id must match [a-z0-9_], 2-40 chars")
        else:
            res.meta = meta
    if not _has_apply(tree):
        res.add('block', 'manifest', 'no apply(api) function defined')

    _static_safety(tree, res)
    _content_filter(src, res, 'code')
    if meta:
        blob = ' '.join(str(meta.get(k, '')) for k in
                        ('name', 'author', 'description'))
        _content_filter(blob, res, 'metadata')

    virustotal_scan(data, res)
    return res
