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
CACHE_TTL_MAX = 3 * 3600          # signed URLs live ~3.2h — cache up to that
CACHE_SAFETY_MARGIN = 600         # re-resolve this long before signature expiry
ALLOWED_STREAM_HOSTS = ("testwave.cc", "de5.net", "pw.live", "aryavidya.cc")

# E2E job handling: resolve returns immediately with status=processing; a
# background thread polls the upstream job (minutes are normal) and writes
# the finished result into the cache. Clients poll our fast cache instead
# of holding a connection against Render's ~61s edge timeout.
JOB_TIMEOUT = 900                 # upstream jobs observed completing in minutes
JOB_TTL = 900                     # how long a processing entry stays valid
ERROR_TTL = 60                    # short negative cache after a job/resolve failure

_cache = {}
_locks = {}
_guard = threading.Lock()
_jobs = {}                        # video_id -> {started, progress, ph}

# Circuit breaker: N consecutive fresh-resolve failures opens the breaker for
# a cooldown — new requests fail fast (503) instead of piling onto a dead
# upstream; cache and in-flight jobs keep serving.
_BREAKER = {"fail": 0, "open_until": 0.0}
BREAKER_THRESHOLD = 5
BREAKER_COOLDOWN = 30.0

# Background refresh: entries are re-resolved REFRESH_LEAD seconds before
# they go stale, so user requests almost always hit a warm cache (<100ms).
REFRESH_LEAD = 300
REFRESH_RETRY = 60
_refresh_stats = {"ok": 0, "fail": 0, "last_at": 0, "last_error": ""}


def _store(video_id, data, params):
    now = time.time()
    exp = data.get("expires_at")
    if exp:
        cache_until = max(now + 60,
                          min(exp - CACHE_SAFETY_MARGIN,
                              now + CACHE_TTL_MAX))
    else:
        cache_until = now + CACHE_TTL_FALLBACK
    refresh_at = max(now + 60, cache_until - REFRESH_LEAD)
    with _guard:
        _cache[video_id] = {"data": data, "cache_until": cache_until,
                            "refresh_at": refresh_at, "params": params}


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


def _breaker_record(ok):
    with _guard:
        if ok:
            _BREAKER["fail"] = 0
        else:
            _BREAKER["fail"] += 1
            if _BREAKER["fail"] >= BREAKER_THRESHOLD:
                _BREAKER["open_until"] = time.time() + BREAKER_COOLDOWN
                _BREAKER["fail"] = 0


def _breaker_open():
    with _guard:
        return time.time() < _BREAKER["open_until"]


def _start_job(video_id, ctx, params):
    """Spawn the background E2E-job worker and seed a processing cache entry."""
    with _guard:
        if video_id in _jobs:
            return
        _jobs[video_id] = {"started": time.time(), "progress": None, "ph": None}
        _cache[video_id] = {
            "data": {"status": "processing", "job_id": ctx["job_id"],
                     "video_id": video_id, "progress": None, "ph": None,
                     "title": ctx["page"].get("title") or params.get("title"),
                     "poster": ctx["page"].get("poster") or params.get("poster")},
            "cache_until": time.time() + JOB_TTL,
            "refresh_at": time.time() + JOB_TTL,
            "params": params,
        }
    av.stats["job_started"] += 1
    threading.Thread(target=_job_worker, args=(video_id, ctx, params),
                     daemon=True).start()


def _job_worker(video_id, ctx, params):
    def on_progress(p, ph):
        with _guard:
            job = _jobs.get(video_id)
            if job:
                job["progress"] = p
                job["ph"] = ph
            ent = _cache.get(video_id)
            if ent and ent["data"].get("status") == "processing":
                ent["data"]["progress"] = p
                ent["data"]["ph"] = ph

    try:
        started = time.time()
        video_url = av.wait_for_job(ctx, timeout=JOB_TIMEOUT, interval=2.0,
                                    on_progress=on_progress)
        ctx["plain"]["video_url"] = video_url
        data = av._build_result(ctx["page"], ctx["plain"], video_url,
                                ctx["video_id"], ctx["batch_id"], started, 1)
        _store(video_id, data, params)
        av.stats["job_completed"] += 1
    except Exception as e:
        av.stats["job_failed"] += 1
        with _guard:
            _cache[video_id] = {
                "data": {"status": "error", "error": str(e)[:200],
                         "job_id": ctx["job_id"], "video_id": video_id},
                "cache_until": time.time() + ERROR_TTL,
                "refresh_at": time.time() + ERROR_TTL,
                "params": params,
            }
    finally:
        with _guard:
            _jobs.pop(video_id, None)


@app.get("/api/health")
def health():
    with _guard:
        entries = len(_cache)
        jobs = len(_jobs)
        breaker_open = time.time() < _BREAKER["open_until"]
    return jsonify(ok=True, service="eduhubpi-video-api", upstream=av.BASE,
                   time=int(time.time()), cache_entries=entries,
                   refresh=dict(_refresh_stats), jobs=jobs,
                   breaker_open=breaker_open, stats=dict(av.stats))


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

    params = {"batch_id": batch_id, "title": title, "poster": poster,
              "subject_id": subject_id, "topic_id": topic_id}
    lock = _lock_for(video_id)
    with lock:
        with _guard:
            ent = _cache.get(video_id)
        if ent and not force and time.time() < ent["cache_until"]:
            data = ent["data"]
            if data.get("status") == "processing":
                return jsonify(ok=True, cached=True, status="processing",
                               video_id=video_id, job_id=data.get("job_id"),
                               progress=data.get("progress"), ph=data.get("ph"),
                               poll_ms=2000)
            if data.get("status") == "error":
                return jsonify(ok=False, retryable=True,
                               error=data.get("error") or "upstream error"), 502
            out = dict(data)
            out.update(ok=True, cached=True)
            out["playback_url"] = _playback_url(out["stream_url"])
            return jsonify(out)

        if _breaker_open():
            with _guard:
                retry_after = max(1, int(_BREAKER["open_until"] - time.time()))
            resp = jsonify(ok=False, retryable=True,
                           error="upstream temporarily unavailable "
                                 "(circuit open) — retry shortly",
                           retry_after=retry_after)
            resp.headers["Retry-After"] = str(retry_after)
            return resp, 503

        try:
            data = av.resolve(video_id, batch_id, title=title, poster=poster,
                              subject_id=subject_id, topic_id=topic_id,
                              job_wait=0)
        except av.JobInProgress as j:
            _start_job(video_id, j.ctx, params)
            with _guard:
                jd = (_cache.get(video_id) or {}).get("data", {})
            return jsonify(ok=True, status="processing", video_id=video_id,
                           job_id=jd.get("job_id"), progress=jd.get("progress"),
                           ph=jd.get("ph"), poll_ms=2000)
        except av.UpstreamError as e:
            _breaker_record(False)
            return jsonify(ok=False, error=str(e)), 502
        _breaker_record(True)

        _store(video_id, data, params)

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


def _refresh_entry(video_id):
    with _guard:
        ent = _cache.get(video_id)
    if not ent:
        return
    if (ent.get("data") or {}).get("status") == "processing":
        return  # job worker owns this entry
    params = ent.get("params") or {}
    lock = _lock_for(video_id)
    with lock:
        with _guard:
            ent = _cache.get(video_id)
        if not ent or ent.get("refresh_at", 0) > time.time():
            return
        try:
            data = av.resolve(video_id, params.get("batch_id") or "",
                              title=params.get("title"),
                              poster=params.get("poster"),
                              subject_id=params.get("subject_id"),
                              topic_id=params.get("topic_id"),
                              job_wait=0)
        except av.JobInProgress as j:
            _start_job(video_id, j.ctx, params)
            return
        except Exception as e:
            _breaker_record(False)
            with _guard:
                if video_id in _cache:
                    _cache[video_id]["refresh_at"] = time.time() + REFRESH_RETRY
            _refresh_stats["fail"] += 1
            _refresh_stats["last_error"] = str(e)[:120]
            _refresh_stats["last_at"] = int(time.time())
            return
        _breaker_record(True)
        _store(video_id, data, params)
        _refresh_stats["ok"] += 1
        _refresh_stats["last_at"] = int(time.time())


def _refresher_loop():
    while True:
        time.sleep(30)
        with _guard:
            due = [v for v, e in _cache.items()
                   if e.get("refresh_at", 0) <= time.time()]
        for v in due:
            try:
                _refresh_entry(v)
            except Exception:
                pass


threading.Thread(target=_refresher_loop, daemon=True).start()


@app.errorhandler(404)
def not_found(_e):
    return jsonify(ok=False, error="not found"), 404


@app.errorhandler(500)
def server_error(_e):
    return jsonify(ok=False, error="internal error"), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8787, threaded=True)
