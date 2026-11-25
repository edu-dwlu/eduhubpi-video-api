"""EduHubPi video API — upstream client for stream.aryavidya.cc.

Implements the full cracked video-resolution chain (RECON.md Part C):
  play.php -> anti-scraper challenge -> hidden inputs -> PoW -> POST
  -> AES-256-CBC decrypt -> (optional E2E job poll) -> signed m3u8 URL.
"""

import base64
import hashlib
import json
import os
import random
import re
import shutil
import subprocess
import threading
import time
import urllib.parse

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

BASE = "https://stream.aryavidya.cc"
E2E_STATUS_URL = "https://status.streamfiles.eu.org/statusforApp/"
UA = (
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36"
)

DECOY_MARKERS = ("CDN_332", "IP_DRC", "buffer underflow", "high latency", "dropped")

# CDN requires browser-like fetch metadata (Sec-Fetch-*) or it returns 403.
STREAM_HEADERS = {
    "User-Agent": UA,
    "Referer": BASE + "/",
    "Origin": BASE,
    "Accept": "*/*",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "cross-site",
}


class UpstreamError(Exception):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


class JobInProgress(Exception):
    """E2E job detected in payload (fallback_polling) — poll async via wait_for_job."""

    def __init__(self, ctx):
        super().__init__("e2e job pending: %s" % ctx.get("job_id"))
        self.ctx = ctx


# Lightweight counters, surfaced by /api/health (observability).
stats = {"resolves": 0, "challenge_solved": 0, "job_started": 0,
         "job_completed": 0, "job_failed": 0}

# _pw_sec_chk is valid ~1h (max-age=3600) — reuse it across resolves so
# repeat requests skip the challenge GET entirely (speed + fewer upstream hits).
_cookie_lock = threading.Lock()
_pw_cookie = {"val": "", "exp": 0.0}


def _get_pw_cookie():
    with _cookie_lock:
        if _pw_cookie["val"] and time.time() < _pw_cookie["exp"]:
            return _pw_cookie["val"]
    return ""


def _set_pw_cookie(val, ttl=3600):
    with _cookie_lock:
        _pw_cookie["val"] = val or ""
        _pw_cookie["exp"] = time.time() + (ttl if val else 0.0)


# Optional residential proxy for the RESOLVE chain only — the challenge/PoW
# flow rejects datacenter IPs (Render etc). Config lives in resolve_proxy.conf
# (file wins when it has a value) with EDUHUBPI_RESOLVE_PROXY as fallback;
# the CDN stream proxy in server.py never uses this.
PROXY_CONF = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "resolve_proxy.conf")


def _load_resolve_proxy():
    """File first (edited any time, re-read every call), then env fallback."""
    try:
        with open(PROXY_CONF, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    return line
    except OSError:
        pass
    return os.environ.get("EDUHUBPI_RESOLVE_PROXY", "").strip()


RESOLVE_PROXY = _load_resolve_proxy()  # import-time snapshot (probe scripts)


def _resolve_proxies():
    proxy = _load_resolve_proxy()  # live read: file edits apply immediately
    if proxy:
        return {"http": proxy, "https": proxy}
    return {}


def _new_session():
    s = requests.Session()
    proxies = _resolve_proxies()
    if proxies:
        s.proxies.update(proxies)
    s.headers.update({
        "User-Agent": UA,
        "Referer": BASE + "/",
        "Accept-Language": "en-US,en;q=0.9",
    })
    chk = _get_pw_cookie()
    if chk:
        s.cookies.set("_pw_sec_chk", chk, domain="stream.aryavidya.cc", path="/")
    return s


def _play_url(video_id, batch_id="", title=None, poster=None,
              subject_id=None, topic_id=None):
    q = {"video_url": "", "video_id": video_id}
    if batch_id:
        q["batch_id"] = batch_id
    if title:
        q["title"] = title
    if poster:
        q["poster"] = poster
    if subject_id:
        q["subject_id"] = subject_id
    if topic_id:
        q["topic_id"] = topic_id
    return BASE + "/play.php?" + urllib.parse.urlencode(q)


def solve_challenge(html):
    """Extract the 32-char _pw_sec_chk token from the challenge page."""
    def span_val(sid, attr):
        m = re.search(r"<span id=['\"]%s['\"][^>]*>" % re.escape(sid), html)
        if not m:
            return ""
        tag = m.group(0)
        if attr == "innerHTML":
            end = html.find("</span>", m.end())
            return html[m.end():end]
        am = re.search(r"%s=['\"]([^'\"]*)['\"]" % re.escape(attr), tag)
        return am.group(1) if am else ""

    stmts = re.findall(
        r"_p(?:\.push\(|\[_p\.length\]\s*=\s*)document\.getElementById\(['\"](s_[0-9a-f]+)['\"]\)\."
        r"(innerHTML|getAttribute\(['\"]([^'\"]+)['\"]\))",
        html,
    )
    order = []
    for sid, kind, attr in stmts:
        order.append(span_val(sid, "innerHTML" if kind == "innerHTML" else attr))
    token = "".join(order)
    if len(token) != 32:
        raise UpstreamError("challenge parse failed (token len %d)" % len(token))
    return token


def _input(html, input_id):
    m = re.search(r'<input[^>]*id="%s"[^>]*value="([^"]*)"' % re.escape(input_id), html)
    if not m:
        m = re.search(r'<input[^>]*value="([^"]*)"[^>]*id="%s"' % re.escape(input_id), html)
    return m.group(1) if m else ""


def extract_page(html):
    """Pull JWT/PoW inputs + video metadata hidden fields from the real play page."""
    token = _input(html, "data-jwt-token")
    if not token:
        raise UpstreamError("no data-jwt-token on page (challenge not cleared?)")
    return {
        "token": token,
        "xfunc": _input(html, "sys-x-func"),
        "trc": _input(html, "sys-trc-id"),
        "auth": _input(html, "sys-auth-lvl") or "0000",
        "video_id": _input(html, "data-video-id"),
        "batch_id": _input(html, "data-batch-id"),
        "subject_id": _input(html, "data-subject-id"),
        "topic_id": _input(html, "data-topic-id"),
        "title": _input(html, "data-title"),
        "poster": _input(html, "data-poster"),
        "is_live": _input(html, "data-is-live"),
    }


def solve_pow(xfunc_b64, trc, auth, env_sig="env_1_ok"):
    """Find v_stamp where sys-x-func(seed, v_stamp) starts with auth.

    The upstream randomizes the hash per page (MD5/SHA1/...), so the exact
    JS function is executed in Node (same semantics as the browser), with a
    Python fallback for the known SHA1/MD5 templates.
    """
    seed = trc + "_" + env_sig
    node = shutil.which("node")
    if node:
        script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pow.js")
        try:
            out = subprocess.run(
                [node, script, xfunc_b64, seed, auth],
                capture_output=True, text=True, timeout=60,
            )
            data = json.loads(out.stdout or "{}")
            if "n" in data:
                return data["n"]
        except Exception:
            pass
    return _solve_pow_python(xfunc_b64, seed, auth)


def _solve_pow_python(xfunc_b64, seed, auth):
    try:
        src = base64.b64decode(xfunc_b64).decode("utf8", "replace")
    except Exception:
        raise UpstreamError("sys-x-func not decodable")
    m = re.search(r"CryptoJS\.(MD5|SHA1|SHA256|SHA512)", src)
    if not m:
        raise UpstreamError("unexpected sys-x-func payload")
    alg = {"MD5": "md5", "SHA1": "sha1",
           "SHA256": "sha256", "SHA512": "sha512"}[m.group(1)]
    seed_b = seed.encode()
    n = 0
    while True:
        h = hashlib.new(alg, seed_b + str(n).encode() + seed_b).hexdigest()
        if h.startswith(auth):
            return n
        n += 1
        if n > 5_000_000:
            raise UpstreamError("PoW did not converge")


def decrypt_payload(enc_b64, v_stamp, chk):
    key = hashlib.sha256((str(v_stamp) + chk + "pw_secure_resp").encode()).digest()
    iv = hashlib.md5((chk + str(v_stamp) + "pw_secure_iv").encode()).digest()
    ct = base64.b64decode(enc_b64)
    pt = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16)
    return json.loads(pt.decode("utf8"))


def _policy_expiry(url):
    m = re.search(r"[?&]Policy=([^&]+)", url)
    if not m:
        return None
    pol = m.group(1)
    try:
        raw = base64.b64decode(pol + "=" * (-len(pol) % 4)).decode("utf8", "replace")
        m2 = re.search(r'"AWS:EpochTime"\s*:\s*(\d+)', raw)
        return int(m2.group(1)) if m2 else None
    except Exception:
        return None


def _job_urls(job_id, v_stamp, chal, status_url=""):
    """Status URL candidates (live deep probe 22 Nov 2026, RECON C8).

    1. streamfiles bare path — no query at all: works without v/chal (the
       service needs no auth) and kept working during a window when the
       query form transiently 404'd on the same host.
    2. streamfiles path-segment + v/chal query — the player's exact form;
       with correct params the service returns `s` AES-encoded instead of
       plain atob base64 (same URL either way).
    3. payload status_url (heroku) bare — answers {c,s,p,ph} while the job
       runs, but its terminal schema is {status:"success",video_url} with a
       foreign key: usable as a done-signal, decode may fail (poll_e2e
       rotates back for a decodable form).
    """
    base = E2E_STATUS_URL.rstrip("/")
    jid = urllib.parse.quote(str(job_id))
    q = "v=%s&chal=%s" % (urllib.parse.quote(str(v_stamp)),
                           urllib.parse.quote(str(chal)))
    urls = [base + "/" + jid,
            base + "/" + jid + "?" + q]
    if status_url:
        su = str(status_url).strip()
        if "{job_id}" in su:
            su = su.replace("{job_id}", jid)
        elif str(job_id) not in su:
            sep = "&" if "?" in su else "?"
            su = su + sep + "job_id=" + jid
        urls.append(su)
    return urls


def _decode_job_url(s, key, iv):
    """Decode the c=1 `s` field: AES-256-CBC first (payload key/iv), atob fallback."""
    try:
        pt = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(
            base64.b64decode(s)), 16).decode("utf8", "replace")
        if pt.startswith("http"):
            return pt
    except Exception:
        pass
    try:
        pt = base64.b64decode(s).decode("utf8")
        if pt.startswith("http"):
            return pt
    except Exception:
        pass
    raise UpstreamError("cannot decode e2e job url (s is neither AES/http nor atob/http)")


def poll_e2e(job_id, v_stamp, chal, key=None, iv=None, status_url="",
             timeout=900.0, interval=2.0, on_progress=None):
    """Poll an E2E job until terminal response (RECON C8, deep-probed 22 Nov).

    Response shapes (live-verified):
      streamfiles: {c,s,p,ph,e} — c=0 in progress (p=% , ph=phase);
        c=1 + s success (s = AES with payload key/iv when v+chal correct,
        plain atob base64 otherwise); c=2 or e=1 failure.
      heroku status_url in-progress: {c,p,ph} (same);
        terminal: {status:"success", video_url:<foreign-key blob>} — decode
        with our key may fail → rotate to a decodable candidate; if every
        candidate stays undecodable, raise "re-resolve needed" (a fresh
        resolve chain then returns the flipped direct URL).
      unknown job_id: bare {c:0} with NO p forever → fail fast after 15
      consecutive such polls (phantom in-progress guard).
    """
    if key is None:
        key = hashlib.sha256((str(v_stamp) + chal + "pw_secure_resp").encode()).digest()
    if iv is None:
        iv = hashlib.md5((chal + str(v_stamp) + "pw_secure_iv").encode()).digest()
    urls = _job_urls(job_id, v_stamp, chal, status_url)
    deadline = time.time() + timeout
    last = None
    idx = 0
    no_p_streak = 0          # consecutive c=0 responses lacking p (phantom jobs)
    undecodable_streak = 0   # consecutive terminal successes we cannot decode
    while time.time() < deadline:
        url = urls[idx % len(urls)]
        try:
            r = requests.get(url, timeout=15, proxies=_resolve_proxies(),
                             headers={"User-Agent": UA, "Referer": BASE + "/"})
            j = r.json()
            last = j
            if r.status_code == 200:
                # heroku terminal schema (foreign-key blob)
                if j.get("status") == "success" and j.get("video_url"):
                    try:
                        return _decode_job_url(j["video_url"], key, iv)
                    except UpstreamError:
                        undecodable_streak += 1
                        if undecodable_streak >= 3:
                            raise UpstreamError(
                                "e2e job complete but url undecodable on all"
                                " candidates — re-resolve needed")
                        idx += 1
                        time.sleep(interval)
                        continue
                c = j.get("c")
                if c == 1 and j.get("s"):
                    try:
                        return _decode_job_url(j["s"], key, iv)
                    except UpstreamError:
                        undecodable_streak += 1
                        if undecodable_streak >= 3:
                            raise UpstreamError(
                                "e2e job complete but url undecodable on all"
                                " candidates — re-resolve needed")
                        idx += 1
                        time.sleep(interval)
                        continue
                if c == 2 or j.get("e") == 1:
                    raise UpstreamError("e2e job failed: %r" % {
                        k: j.get(k) for k in ("c", "e", "p", "ph")})
                if c == 0:
                    if j.get("p") is None:
                        no_p_streak += 1
                        if no_p_streak >= 15:
                            raise UpstreamError(
                                "e2e job not found (status service has no"
                                " record of %s)" % job_id)
                    else:
                        no_p_streak = 0
                if on_progress and j.get("p") is not None:
                    try:
                        on_progress(j.get("p"), j.get("ph"))
                    except Exception:
                        pass
            else:
                idx += 1  # rotate to next candidate (404 etc.)
        except UpstreamError:
            raise
        except Exception:
            idx += 1
        time.sleep(interval)
    raise UpstreamError("e2e job did not complete: %r" % (last,))


def wait_for_job(ctx, timeout=900.0, interval=2.0, on_progress=None):
    """Poll a JobInProgress ctx (same-session key/iv/chal) until terminal."""
    return poll_e2e(ctx["job_id"], ctx["v_stamp"], ctx["chal"],
                    key=ctx["key"], iv=ctx["iv"],
                    status_url=ctx.get("status_url") or "",
                    timeout=timeout, interval=interval,
                    on_progress=on_progress)


def _post_video_url(sess, token, v_stamp, env_sig):
    headers = {
        "Origin": BASE,
        "Referer": BASE + "/",
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "sec-ch-ua": '"Chromium";v="131", "Not_A Brand";v="24"',
        "sec-ch-ua-mobile": "?1",
        "sec-ch-ua-platform": '"Android"',
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
    }
    body = {"token": token, "v_stamp": v_stamp, "env_sig": env_sig}
    # PW (penpencilvdo) videos take ~19-25s here (verified against the
    # official player: its own POST measured 19.1s). 15s used to kill
    # every PW resolve mid-flight → read-timeout storms → CF 502.
    r = sess.post(BASE + "/api/video-url-details.php", json=body,
                  headers=headers, timeout=30)
    try:
        data = r.json()
    except Exception:
        raise UpstreamError("non-json response (status %s)" % r.status_code,
                            status=r.status_code)
    if r.status_code != 200 or not data.get("success"):
        msg = str(data.get("error") or data.get("message") or "resolve failed")
        raise UpstreamError(msg, status=r.status_code)
    return data


def _build_result(page, plain, video_url, video_id, batch_id, started, attempt=1):
    return {
        "video_id": page["video_id"] or video_id,
        "batch_id": page["batch_id"] or batch_id,
        "subject_id": page["subject_id"],
        "topic_id": page["topic_id"],
        "title": page["title"],
        "poster": page["poster"],
        "is_live": page["is_live"] == "1",
        "urlType": plain.get("urlType") or "penpencilvdo",
        "stream_url": video_url,
        "drm": {
            "has_drm": bool(plain.get("license_url")),
            "license_url": plain.get("license_url") or "",
            "license_token": plain.get("license_token") or "",
            "key_id": plain.get("signed_key_id") or "",
            "key_value": plain.get("signed_key") or "",
        },
        "expires_at": _policy_expiry(video_url),
        "attempts": attempt,
        "resolved_in_s": round(time.time() - started, 1),
    }


def resolve(video_id, batch_id="", title=None, poster=None,
            subject_id=None, topic_id=None,
            max_attempts=6, min_delay=0.15, max_delay=0.6, job_wait=0.0):
    """Resolve a video to a signed m3u8 URL.

    Fast chains (~3-5s) with error-classified backoff: application-level
    rejections (CDN_332 / decoy / challenge) get escalating delays to ride
    out upstream rate windows; network blips retry quickly. Total wall
    budget stays under ~55s because Render's edge drops connections ~61s.

    E2E jobs (payload fallback_polling): with job_wait=0 (default) raises
    JobInProgress immediately carrying a ctx for wait_for_job() — callers
    should poll async so the HTTP request never blocks on a multi-minute
    job. job_wait>0 polls synchronously for up to that many seconds.
    """
    if not video_id:
        raise UpstreamError("video_id required")
    started = time.time()
    RATE_BACKOFF = (1.0, 2.0, 4.0, 8.0, 12.0)
    NET_BACKOFF = (0.5, 1.0, 2.0, 3.0, 4.0)
    BUDGET = 55.0
    last_err = None
    for attempt in range(1, max_attempts + 1):
        sess = _new_session()
        is_net = False
        try:
            url = _play_url(video_id, batch_id, title, poster, subject_id, topic_id)
            r = sess.get(url, timeout=20)
            html = r.text
            if "Securing Player" in html:
                chk = solve_challenge(html)
                _set_pw_cookie(chk)
                stats["challenge_solved"] += 1
                sess.cookies.set("_pw_sec_chk", chk, domain="stream.aryavidya.cc",
                                 path="/")
                r = sess.get(url, timeout=20)
                html = r.text
            page = extract_page(html)
            chk = sess.cookies.get("_pw_sec_chk") or ""
            if not chk:
                raise UpstreamError("missing _pw_sec_chk after challenge")
            v_stamp = solve_pow(page["xfunc"], page["trc"], page["auth"])
            time.sleep(random.uniform(min_delay, max_delay))
            resp = _post_video_url(sess, page["token"], v_stamp, "env_1_ok")
            plain = decrypt_payload(resp["enc_payload"], v_stamp, chk)
            video_url = plain.get("video_url") or ""
            if plain.get("fallback_polling"):
                job_id = str(plain.get("job_id") or "")
                if not job_id:
                    raise UpstreamError("fallback_polling set but job_id missing")
                key = hashlib.sha256(
                    (str(v_stamp) + chk + "pw_secure_resp").encode()).digest()
                iv = hashlib.md5(
                    (chk + str(v_stamp) + "pw_secure_iv").encode()).digest()
                ctx = {
                    "job_id": job_id, "v_stamp": v_stamp, "chal": chk,
                    "key": key, "iv": iv,
                    "status_url": plain.get("status_url") or "",
                    "page": page, "plain": plain,
                    "video_id": page["video_id"] or video_id,
                    "batch_id": page["batch_id"] or batch_id,
                }
                if job_wait and job_wait > 0:
                    video_url = poll_e2e(
                        job_id, v_stamp, chk, key=key, iv=iv,
                        status_url=ctx["status_url"],
                        timeout=min(job_wait,
                                    max(5.0, BUDGET - (time.time() - started))))
                else:
                    raise JobInProgress(ctx)
            if not video_url.startswith("http"):
                raise UpstreamError("no video_url in payload: %r" % sorted(plain))
            stats["resolves"] += 1
            return _build_result(page, plain, video_url,
                                 page["video_id"] or video_id,
                                 page["batch_id"] or batch_id,
                                 started, attempt)
        except UpstreamError as e:
            last_err = e
            # Deterministic upstream breakage: video-url-details answers
            # HTTP 500 {"error":"API Failed"} for videos whose video doc is
            # missing/unlinked upstream (AryaVidya's own SPA gets the same
            # 500 — verified live). Retrying only burns the 55s budget
            # (~48s for 6 attempts); one shot then abort.
            if getattr(e, "status", None) == 500 and str(e) == "API Failed":
                break
        except requests.RequestException as e:
            last_err = UpstreamError("network: %s" % e)
            is_net = True
        if attempt >= max_attempts:
            break
        schedule = NET_BACKOFF if is_net else RATE_BACKOFF
        wait = schedule[min(attempt - 1, len(schedule) - 1)]
        wait += random.uniform(0.0, 0.4)
        if time.time() - started + wait > BUDGET:
            break
        time.sleep(wait)
    raise UpstreamError(
        "resolve failed after %d attempts (last: %s)" % (attempt, last_err),
        status=getattr(last_err, "status", None),
    )
