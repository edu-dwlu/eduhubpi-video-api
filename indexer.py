"""Batch lecture catalog harvester (local-only module).

Walks AryaVidya's XOR-gateway batch API with pure requests and returns
the full lecture map for a batch:

    /v3/batches/{B}/details                  -> subjects
    /v1/batches/{B}/subject/{S}/topics       -> topics (paged)
    /batch-service/.../contents?tagId={T}    -> lectures -> videoDetails.findKey

No selenium, no player flow — this is the catalog half of the indexing
system; the warm (resolve) half lives in server.py where the cache and
locks already exist.  Used by POST /api/index and the auto-index trigger.
"""

import base64
import time

import requests

ENC_KEY = b"fgsbhv235793853rifjb"
BASE = "https://stream.aryavidya.cc"
HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Linux; Android 13) Chrome/120 Mobile"),
    "Referer": BASE + "/",
}
TIMEOUT = 25


class HarvestError(Exception):
    pass


def enc_path(path: str) -> str:
    b = path.encode()
    return base64.b64encode(
        bytes(b[i] ^ ENC_KEY[i % len(ENC_KEY)] for i in range(len(b)))
    ).decode()


def _get(path: str):
    r = requests.get(
        BASE + "/arshya/index.php",
        params={"type": "contents", "metaData": enc_path(path)},
        headers=HEADERS, timeout=TIMEOUT,
    )
    if r.status_code != 200:
        raise HarvestError("gateway %s -> HTTP %s" % (path[:60], r.status_code))
    try:
        data = r.json()
    except Exception:
        raise HarvestError("gateway %s -> non-json" % path[:60])
    if not data.get("success"):
        raise HarvestError("gateway %s -> %s" % (
            path[:60], str(data.get("error"))[:120]))
    return data.get("data")


def _topics(subject_id: str, batch_id: str):
    page = 1
    while True:
        items = _get("/v1/batches/%s/subject/%s/topics?page=%d&limit=50"
                     % (batch_id, subject_id, page)) or []
        if isinstance(items, dict):
            items = items.get("topics") or items.get("list") or []
        for t in items:
            yield t
        if len(items) < 50:
            break
        page += 1
        time.sleep(0.05)


def _lectures(subject_id: str, batch_id: str, tag_id: str):
    skip = 0
    while True:
        items = _get(
            "/batch-service/v3/batch-subject-schedules/%s/subject/%s/"
            "contents?skip=%d&limit=50&contentType=LECTURES"
            "&contentFilter=ALL&tagId=%s"
            % (batch_id, subject_id, skip, tag_id)) or []
        for it in items:
            yield it
        if len(items) < 50:
            break
        skip += 50
        time.sleep(0.05)


def _walk(node, subject_id, subject_name, topic_id, topic_name, out):
    """Recursively collect videoDetails.findKey entries (items may be
    wrapped as {type, data:{...}} depending on endpoint)."""
    if isinstance(node, dict):
        vd = node.get("videoDetails")
        if isinstance(vd, dict) and vd.get("findKey"):
            out[vd["findKey"]] = {
                "title": (vd.get("name") or node.get("topic") or "")[:120],
                "subject": subject_name,
                "topic": topic_name,
                "subject_id": subject_id,
                "topic_id": topic_id,
                "schedule_id": node.get("_id"),
                "status": node.get("status"),
            }
        for v in node.values():
            _walk(v, subject_id, subject_name, topic_id, topic_name, out)
    elif isinstance(node, list):
        for v in node:
            _walk(v, subject_id, subject_name, topic_id, topic_name, out)


def harvest_batch(batch_id: str) -> dict:
    """Full catalog for one batch.  ~10-15s for a 50-lecture batch."""
    if not batch_id or len(batch_id) != 24:
        raise HarvestError("batch_id must be a 24-hex id")
    details = _get("/v3/batches/%s/details" % batch_id)
    if not isinstance(details, dict):
        raise HarvestError("bad batch details payload")
    subjects = details.get("subjects") or []

    lectures = {}
    topic_list = []
    subject_list = []
    for s in subjects:
        sid = s.get("_id")
        if not sid:
            continue
        sname = s.get("subject") or s.get("name") or ""
        subject_list.append({"id": sid, "name": sname})
        for t in _topics(sid, batch_id):
            tid = t.get("_id")
            if not tid:
                continue
            tname = t.get("name") or ""
            topic_list.append({"id": tid, "name": tname,
                               "slug": t.get("slug") or "",
                               "subject_id": sid})
            for item in _lectures(sid, batch_id, tid):
                node = item.get("data") if isinstance(item.get("data"), dict) \
                    else item
                _walk(node, sid, sname, tid, tname, lectures)
            time.sleep(0.05)
        time.sleep(0.05)

    return {
        "batch_id": batch_id,
        "name": details.get("name") or "",
        "subjects": subject_list,
        "topics": topic_list,
        "lectures": lectures,
        "indexed_at": int(time.time()),
    }
