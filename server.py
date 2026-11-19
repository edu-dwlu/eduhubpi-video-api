"""EduHubPi video API — Flask service (Render-ready).

Endpoints:
  GET /api/health
  GET /api/videos/resolve?video_id=...&batch_id=...[&force=1]
  GET /api/videos/stream?u=<signed upstream url>   (CORS-safe proxy, playlist rewrite)
"""

import re
import threading
import time
import urllib.parse

import requests
from flask import Flask, Response, jsonify, request, stream_with_context
from flask_cors import CORS
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

import aryavidya as av

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# The CDN hostname CNAMEs through rotating herokudns.com targets, so DNS
# resolution flaps (intermittent errno 7 / connection resets). Retry hard.
_upstream = requests.Session()
_upstream.mount("https://", HTTPAdapter(max_retries=Retry(
    total=4, connect=4, read=4, backoff_factor=1.0,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=frozenset(["GET", "HEAD"]),
)))
_upstream.mount("http://", HTTPAdapter(max_retries=Retry(
    total=4, connect=4, read=4, backoff_factor=1.0,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=frozenset(["GET", "HEAD"]),
)))

CACHE_TTL_FALLBACK = 1800
CACHE_SAFETY_MARGIN = 600
ALLOWED_STREAM_HOSTS = ("testwave.cc", "pw.live", "aryavidya.cc")

_cache = {}
_locks = {}
_guard = threading.Lock()


def _lock_for(key):
    with _guard:
        if key not in _locks:
            _locks[key] = threading.Lock()
        return _locks[key]


def _allowed_stream_url(url):
    try:
        p = urllib.parse.urlparse(url)
    except Exception:
        return False
    if p.scheme not in ("http", "https") or not p.hostname:
        return False
    host = p.hostname.lower()
    return any(host == h or host.endswith("." + h) for h in ALLOWED_STREAM_HOSTS)


@app.get("/api/health")
def health():
    return jsonify(ok=True, service="eduhubpi-video-api", upstream=av.BASE,
                   time=int(time.time()))


@app.get("/api/videos/resolve")
def resolve():
    video_id = (request.args.get("video_id") or "").strip()
    batch_id = (request.args.get("batch_id") or "").strip()
    title = (request.args.get("title") or "").strip() or None
    poster = (request.args.get("poster") or "").strip() or None
    subject_id = (request.args.get("subject_id") or "").strip() or None
    topic_id = (request.args.get("topic_id") or "").strip() or None
    force = (request.args.get("force") or "") in ("1", "true", "yes")
    if not video_id:
        return jsonify(ok=False, error="video_id query param required"), 400
    if not re.fullmatch(r"[0-9a-fA-F]{24}", video_id):
        return jsonify(ok=False, error="video_id must be a 24-hex id"), 400

    lock = _lock_for(video_id)
    with lock:
        ent = _cache.get(video_id)
        if ent and not force and time.time() < ent["cache_until"]:
            out = dict(ent["data"])
            out.update(ok=True, cached=True)
            out["playback_url"] = _playback_url(out["stream_url"])
            return jsonify(out)

        try:
            data = av.resolve(video_id, batch_id, title=title, poster=poster,
                              subject_id=subject_id, topic_id=topic_id)
        except av.UpstreamError as e:
            return jsonify(ok=False, error=str(e)), 502

        exp = data.get("expires_at")
        if exp:
            cache_until = max(time.time() + 60,
                              min(exp - CACHE_SAFETY_MARGIN,
                                  time.time() + CACHE_TTL_FALLBACK))
        else:
            cache_until = time.time() + CACHE_TTL_FALLBACK
        _cache[video_id] = {"data": data, "cache_until": cache_until}

        out = dict(data)
        out.update(ok=True, cached=False)
        out["playback_url"] = _playback_url(data["stream_url"])
        return jsonify(out)


def _playback_url(stream_url):
    q = urllib.parse.urlencode({"u": stream_url})
    return request.host_url.rstrip("/") + "/api/videos/stream?" + q


@app.get("/api/videos/stream")
def stream():
    url = request.args.get("u") or ""
    if not _allowed_stream_url(url):
        return jsonify(ok=False, error="host not allowed"), 403

    upstream_headers = dict(av.STREAM_HEADERS)
    try:
        up = _upstream.get(url, headers=upstream_headers, timeout=30, stream=True)
    except requests.RequestException as e:
        return jsonify(ok=False, error="upstream fetch failed: %s" % e), 502

    if up.status_code != 200:
        body = up.content[:300]
        up.close()
        return jsonify(ok=False, error="upstream status %s" % up.status_code,
                       detail=body.decode("utf8", "replace")), 502

    first = up.raw.read(65536, decode_content=True)
    is_playlist = first.lstrip().startswith(b"#EXTM3U")

    if is_playlist:
        rest = up.raw.read(decode_content=True)
        up.close()
        text = (first + rest).decode("utf8", "replace")
        text = _rewrite_playlist(text, url)
        return Response(text, mimetype="application/vnd.apple.mpegurl", headers={
            "Access-Control-Allow-Origin": "*",
            "Cache-Control": "no-store",
        })

    def generate():
        yield first
        for chunk in up.iter_content(65536):
            yield chunk
        up.close()

    resp = Response(stream_with_context(generate()),
                    mimetype=up.headers.get("Content-Type") or
                            "application/octet-stream")
    resp.headers["Access-Control-Allow-Origin"] = "*"
    exp = av._policy_expiry(url)
    if exp and exp > time.time():
        resp.headers["Cache-Control"] = "public, max-age=%d" % max(
            0, min(exp - int(time.time()) - 60, 86400))
    else:
        resp.headers["Cache-Control"] = "public, max-age=600"
    return resp


def _rewrite_playlist(text, base_url):
    base = base_url.split("?")[0]

    def enc(u):
        return "/api/videos/stream?" + urllib.parse.urlencode({"u": u})

    out = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            out.append(line)
            continue
        if stripped.startswith("#"):
            if "URI=" in stripped:
                def repl(m):
                    u = urllib.parse.urljoin(base, m.group(2))
                    return m.group(1) + enc(u) + m.group(3)
                import re as _re
                stripped = _re.sub(r'(URI=")([^"]+)(")', repl, stripped)
            out.append(stripped)
        else:
            out.append(enc(urllib.parse.urljoin(base, stripped)))
    return "\n".join(out) + "\n"


@app.errorhandler(404)
def not_found(_e):
    return jsonify(ok=False, error="not found"), 404


@app.errorhandler(500)
def server_error(_e):
    return jsonify(ok=False, error="internal error"), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8787, threaded=True)
