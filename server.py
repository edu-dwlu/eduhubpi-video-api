"""EduHubPi video API — Flask service (Render-ready).

Endpoints:
  GET /api/health
  GET /api/videos/resolve?video_id=...&batch_id=...[&force=1]
  GET /api/videos/stream?u=<signed upstream url>   (CORS-safe proxy, playlist rewrite)
  POST /api/index?batch_id=...[&warm=0][&force=1]  (index a batch's lectures)
  GET  /api/index?batch_id=...                     (index status)
"""

import json
import os
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
import indexer

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
ERROR_TTL = 300                   # negative cache after a job/resolve failure
                                  # (5 min: stops player retries from re-arming
                                  #  CDN_332 storms every minute)

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

# Batch lecture indexing: catalog (indexer.harvest_batch) + a warm pass
# that pre-resolves every lecture into _cache, so player requests hit
# <100ms.  Videos whose upstream answer is the deterministic 500
# "API Failed" (AryaVidya's own SPA is stuck on them too) go into
# broken[] and short-circuit instantly on resolve; re-probed every
# INDEX_RECHECK seconds by the refresher loop.
_index = {}                        # batch_id -> index state dict
_index_locks = {}
INDEX_RECHECK = 20 * 60
_index_stats = {"started": 0, "warmed": 0, "broken_marked": 0}

# State persistence: _cache and _index live in process memory only, so a
# gunicorn restart used to wipe every warmed URL and index catalog.  We
# snapshot both to state.json every ~30s (and on index completion) and
# reload the snapshot on boot — restarts are lossless.  In-flight work
# (harvesting/warming entries, processing jobs) is intentionally NOT
# saved: it dies with the process and re-kicks automatically.
STATE_FILE = os.environ.get("EDUHUBPI_STATE_FILE") or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "state.json")
STATE_MAX_AGE = 24 * 3600          # ignore snapshots older than this
_state_last_save = 0.0
_state_meta = {"saved_at": 0, "restored_cache": 0, "restored_index": 0}


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
        try:
            video_url = av.wait_for_job(ctx, timeout=JOB_TIMEOUT, interval=2.0,
                                        on_progress=on_progress)
        except av.UpstreamError as e:
            if "re-resolve" not in str(e):
                raise
            # Job finished but every status host's terminal blob used a
            # foreign key — a fresh resolve chain now returns the flipped
            # direct URL (payload drops job fields after completion, C8).
            data = av.resolve(video_id, batch_id=params.get("batch_id") or "",
                              title=params.get("title"),
                              poster=params.get("poster"),
                              subject_id=params.get("subject_id"),
                              topic_id=params.get("topic_id"),
                              job_wait=0)
            _store(video_id, data, params)
            av.stats["job_completed"] += 1
            return
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


# ---- batch lecture indexing ------------------------------------------

def _index_lock_for(batch_id):
    with _guard:
        if batch_id not in _index_locks:
            _index_locks[batch_id] = threading.Lock()
        return _index_locks[batch_id]


def _index_status(batch_id):
    with _guard:
        ent = _index.get(batch_id)
        if not ent:
            return None
        return {
            "ok": True, "batch_id": batch_id, "state": ent.get("state"),
            "name": ent.get("name", ""), "total": ent.get("total", 0),
            "warmed": ent.get("warmed", 0),
            "broken_count": len(ent.get("broken") or {}),
            "broken": sorted(ent.get("broken") or {}),
            "subjects": len(ent.get("subjects") or []),
            "topics": len(ent.get("topics") or []),
            "indexed_at": ent.get("indexed_at", 0),
            "error": ent.get("error", ""),
        }


def _ensure_index(batch_id, warm=True):
    """Start background indexing unless this batch is already running/done."""
    if not re.fullmatch(r"[0-9a-fA-F]{24}", batch_id or ""):
        return None
    with _guard:
        ent = _index.get(batch_id)
        if ent:
            state = ent.get("state")
            if state in ("harvesting", "warming", "done"):
                return ent
            if state == "error" and \
                    time.time() - ent.get("started", 0) < 120:
                return ent          # cool-off before retrying a failed run
    lock = _index_lock_for(batch_id)
    with lock:
        with _guard:
            ent = _index.get(batch_id)
            if ent:
                state = ent.get("state")
                if state in ("harvesting", "warming", "done"):
                    return ent
                if state == "error" and \
                        time.time() - ent.get("started", 0) < 120:
                    return ent
            ent = {"state": "harvesting", "batch_id": batch_id, "name": "",
                   "subjects": [], "topics": [], "lectures": {},
                   "total": 0, "warmed": 0, "broken": {},
                   "indexed_at": 0, "error": "",
                   "started": time.time()}
            _index[batch_id] = ent
            _index_stats["started"] += 1
        threading.Thread(target=_index_worker, args=(batch_id, warm),
                         daemon=True).start()
        return ent


def _mark_broken(batch_id, video_id, error):
    """Record a deterministic upstream-500 video (instant short-circuit)."""
    now = time.time()
    with _guard:
        ent = _index.get(batch_id)
        if not ent:
            return False
        ent.setdefault("broken", {})[video_id] = {
            "error": str(error)[:160], "at": int(now),
            "recheck_at": now + INDEX_RECHECK}
        _index_stats["broken_marked"] += 1
        return True


def _index_worker(batch_id, warm):
    try:
        cat = indexer.harvest_batch(batch_id)
        lectures = cat.get("lectures") or {}
        with _guard:
            ent = _index.get(batch_id)
            if not ent:
                return
            ent.update(name=cat.get("name", ""),
                       subjects=cat.get("subjects") or [],
                       topics=cat.get("topics") or [],
                       lectures=lectures, total=len(lectures),
                       indexed_at=cat.get("indexed_at") or int(time.time()),
                       error="")
            ent["state"] = "warming" if warm else "done"
        if not warm:
            _save_state()
            return
        _warm_batch(batch_id, lectures)
        with _guard:
            ent = _index.get(batch_id)
            if ent and ent.get("state") == "warming":
                ent["state"] = "done"
        _save_state()
    except Exception as e:
        with _guard:
            ent = _index.get(batch_id)
            if ent:
                ent["state"] = "error"
                ent["error"] = str(e)[:200]
        _save_state()


def _warm_batch(batch_id, lectures):
    for vid, meta in list(lectures.items()):
        with _guard:
            ent = _index.get(batch_id)
            if not ent or ent.get("state") != "warming":
                return
        while _breaker_open():      # respect an open breaker — no amplification
            time.sleep(5)
            with _guard:
                ent = _index.get(batch_id)
                if not ent or ent.get("state") != "warming":
                    return
        with _guard:                # already fresh (player beat us to it)?
            c = _cache.get(vid)
            fresh = bool(c) and time.time() < c.get("cache_until", 0) and \
                c.get("data", {}).get("status") != "error"
            in_job = vid in _jobs
        if fresh or in_job:
            with _guard:
                ent = _index.get(batch_id)
                if ent:
                    ent["warmed"] = ent.get("warmed", 0) + 1
            continue
        params = {"batch_id": batch_id, "title": meta.get("title"),
                  "subject_id": meta.get("subject_id"),
                  "topic_id": meta.get("topic_id")}
        lock = _lock_for(vid)
        with lock:
            try:
                data = av.resolve(vid, batch_id, title=meta.get("title"),
                                  subject_id=meta.get("subject_id"),
                                  topic_id=meta.get("topic_id"), job_wait=0)
            except av.JobInProgress as j:
                _start_job(vid, j.ctx, params)
                with _guard:
                    ent = _index.get(batch_id)
                    if ent:
                        ent["warmed"] = ent.get("warmed", 0) + 1
                continue
            except av.UpstreamError as e:
                if getattr(e, "status", None) == 500 and \
                        "API Failed" in str(e):
                    _mark_broken(batch_id, vid, e)
                else:
                    _breaker_record(False)
                continue
            except Exception:
                continue
            _breaker_record(True)
            _store(vid, data, params)
            with _guard:
                ent = _index.get(batch_id)
                if ent:
                    ent["warmed"] = ent.get("warmed", 0) + 1
            _index_stats["warmed"] += 1
        time.sleep(0.3)


def _recheck_broken():
    """Probe up to 2 due broken videos per 30s tick (recover when fixed)."""
    now = time.time()
    due = []
    with _guard:
        for bid, ent in _index.items():
            for vid, b in (ent.get("broken") or {}).items():
                if b.get("recheck_at", 0) <= now:
                    due.append((bid, vid))
    for bid, vid in due[:2]:
        try:
            _recheck_one(bid, vid)
        except Exception:
            pass


def _recheck_one(batch_id, video_id):
    with _guard:
        ent = _index.get(batch_id)
        if not ent or video_id not in (ent.get("broken") or {}):
            return
        meta = (ent.get("lectures") or {}).get(video_id) or {}
    params = {"batch_id": batch_id, "title": meta.get("title"),
              "subject_id": meta.get("subject_id"),
              "topic_id": meta.get("topic_id")}
    lock = _lock_for(video_id)
    with lock:
        try:
            data = av.resolve(video_id, batch_id, title=meta.get("title"),
                              subject_id=meta.get("subject_id"),
                              topic_id=meta.get("topic_id"), job_wait=0)
        except av.JobInProgress as j:
            _start_job(video_id, j.ctx, params)
            with _guard:
                ent = _index.get(batch_id)
                if ent:
                    (ent.get("broken") or {}).pop(video_id, None)
                    ent["warmed"] = ent.get("warmed", 0) + 1
            return
        except Exception as e:
            with _guard:
                ent = _index.get(batch_id)
                b = (ent or {}).get("broken", {}).get(video_id)
                if b:
                    b["error"] = str(e)[:160]
                    b["at"] = int(time.time())
                    b["recheck_at"] = time.time() + INDEX_RECHECK
            return
        _breaker_record(True)
        _store(video_id, data, params)
        with _guard:
            ent = _index.get(batch_id)
            if ent:
                (ent.get("broken") or {}).pop(video_id, None)
                ent["warmed"] = ent.get("warmed", 0) + 1
        _index_stats["warmed"] += 1


@app.post("/api/index")
def index_start():
    batch_id = (request.args.get("batch_id") or "").strip()
    warm = (request.args.get("warm", "1").lower() not in ("0", "false", "no"))
    force = (request.args.get("force", "").lower() in ("1", "true", "yes"))
    if not re.fullmatch(r"[0-9a-fA-F]{24}", batch_id):
        return jsonify(ok=False, error="batch_id must be a 24-hex id"), 400
    if force:
        with _guard:
            ent = _index.get(batch_id)
            running = bool(ent) and ent.get("state") in ("harvesting",
                                                          "warming")
        if not running:
            with _guard:
                _index.pop(batch_id, None)
    _ensure_index(batch_id, warm=warm)
    st = _index_status(batch_id) or {"ok": True, "batch_id": batch_id}
    return jsonify(**st), 202


@app.get("/api/index")
def index_status_ep():
    batch_id = (request.args.get("batch_id") or "").strip()
    if not re.fullmatch(r"[0-9a-fA-F]{24}", batch_id):
        return jsonify(ok=False, error="batch_id must be a 24-hex id"), 400
    st = _index_status(batch_id)
    if not st:
        return jsonify(ok=False, error="batch not indexed"), 404
    return jsonify(**st)


@app.get("/api/health")
def health():
    with _guard:
        entries = len(_cache)
        jobs = len(_jobs)
        indexed = len(_index)
        breaker_open = time.time() < _BREAKER["open_until"]
    return jsonify(ok=True, service="eduhubpi-video-api", upstream=av.BASE,
                   time=int(time.time()), cache_entries=entries,
                   refresh=dict(_refresh_stats), jobs=jobs,
                   indexed=indexed, index_stats=dict(_index_stats),
                   breaker_open=breaker_open, stats=dict(av.stats),
                   state={"file": os.path.basename(STATE_FILE),
                          "saved_at": _state_meta.get("saved_at", 0),
                          "restored_cache": _state_meta.get("restored_cache", 0),
                          "restored_index": _state_meta.get("restored_index", 0),
                          "last_save_at": int(_state_last_save)})


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

    # auto-index: first request carrying a new batch_id kicks off the
    # background catalog+warm index (never blocks this request)
    if batch_id:
        _ensure_index(batch_id)

    # indexed-broken short-circuit: deterministic upstream 500s answer
    # instantly instead of re-running the chain (force=1 bypasses to probe)
    if batch_id and not force:
        with _guard:
            bent = ((_index.get(batch_id) or {}).get("broken") or {}) \
                .get(video_id)
        if bent and time.time() < bent.get("recheck_at", 0):
            wait = max(1, int(bent["recheck_at"] - time.time()))
            resp = jsonify(ok=False, retryable=True, upstream_broken=True,
                           error="video unavailable upstream (AryaVidya "
                                 "API 500) — queued for recheck",
                           recheck_in=wait)
            resp.headers["Retry-After"] = str(wait)
            return resp, 502

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
            marked = False
            if getattr(e, "status", None) == 500 and "API Failed" in str(e):
                # deterministic upstream breakage — record it (when the
                # batch is indexed) for instant short-circuit, and don't
                # trip the breaker: broken videos must not block good ones
                if batch_id:
                    marked = _mark_broken(batch_id, video_id, e)
            else:
                _breaker_record(False)
            if not marked:
                # negative-cache the failure for ERROR_TTL so player
                # retries get an instant 502 instead of re-running a
                # 37-55s CDN_332 storm (force=1 still bypasses to probe)
                with _guard:
                    _cache[video_id] = {
                        "data": {"status": "error", "error": str(e)[:200],
                                 "video_id": video_id},
                        "cache_until": time.time() + ERROR_TTL,
                        "refresh_at": time.time() + ERROR_TTL,
                        "params": params,
                    }
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


def _save_state():
    """Atomically snapshot cache + index to STATE_FILE (restart safety).

    Held under _guard for the whole write so json.dump never iterates a
    dict that another thread is mutating; callers must NOT hold _guard.
    """
    global _state_last_save
    now = time.time()
    with _guard:
        snap = {
            "saved_at": now,
            "cache": {k: v for k, v in _cache.items()
                      if (v.get("data") or {}).get("status") != "processing"},
            "index": {k: v for k, v in _index.items()
                      if v.get("state") in ("done", "error")},
            "index_stats": dict(_index_stats),
        }
        try:
            tmp = STATE_FILE + ".tmp"
            with open(tmp, "w") as f:
                json.dump(snap, f)
            try:
                os.chmod(tmp, 0o600)
            except Exception:
                pass
            os.replace(tmp, STATE_FILE)
            _state_last_save = now
            _state_meta["saved_at"] = int(now)
        except Exception:
            pass


def _load_state():
    """Best-effort restore of a previous snapshot after restart.

    Expired cache URLs are dropped (re-resolve on demand); in-flight
    index states were never saved, so the next resolve re-kicks them.
    """
    if not STATE_FILE:
        return
    try:
        with open(STATE_FILE) as f:
            snap = json.load(f)
    except Exception:
        return
    if not isinstance(snap, dict) or \
            time.time() - float(snap.get("saved_at") or 0) > STATE_MAX_AGE:
        return
    now = time.time()
    n_cache = n_idx = 0
    for vid, ent in (snap.get("cache") or {}).items():
        if not isinstance(ent, dict) or not isinstance(ent.get("data"), dict):
            continue
        if float(ent.get("cache_until") or 0) <= now:
            continue                      # expired — re-resolve on demand
        with _guard:
            _cache[vid] = ent
        n_cache += 1
    for bid, ent in (snap.get("index") or {}).items():
        if not isinstance(ent, dict) or \
                ent.get("state") not in ("done", "error"):
            continue
        lectures = ent.get("lectures") or {}
        with _guard:
            ent["warmed"] = sum(
                1 for v in lectures
                if v in _cache
                and now < _cache[v].get("cache_until", 0)
                and (_cache[v].get("data") or {}).get("status") != "error")
            _index[bid] = ent
        n_idx += 1
    st = snap.get("index_stats")
    if isinstance(st, dict):
        with _guard:
            for k in _index_stats:
                if isinstance(st.get(k), (int, float)):
                    _index_stats[k] = int(st[k])
    _state_meta["restored_cache"] = n_cache
    _state_meta["restored_index"] = n_idx
    print("state restored: %d cache entries, %d batch indexes"
          % (n_cache, n_idx), flush=True)


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
        try:
            if time.time() - _state_last_save >= 30:
                _save_state()
        except Exception:
            pass
        try:
            _recheck_broken()
        except Exception:
            pass
        with _guard:
            due = [v for v, e in _cache.items()
                   if e.get("refresh_at", 0) <= time.time()]
        for v in due:
            try:
                _refresh_entry(v)
            except Exception:
                pass


_load_state()
threading.Thread(target=_refresher_loop, daemon=True).start()


@app.errorhandler(404)
def not_found(_e):
    return jsonify(ok=False, error="not found"), 404


@app.errorhandler(500)
def server_error(_e):
    return jsonify(ok=False, error="internal error"), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8787, threaded=True)
