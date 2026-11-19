# eduhubpi-video-api

EduHubPi video API — resolves signed HLS streams and proxies them CORS-safe.

## Endpoints

- `GET /api/health`
- `GET /api/videos/resolve?video_id=<24-hex>[&batch_id=...][&force=1]`
  → `{ok, playback_url, stream_url, title, poster, expires_at, cached}`
- `GET /api/videos/stream?u=<signed upstream url>`
  → HLS playlist (URIs rewritten through the proxy) or media segment, streamed

No env vars required.

## Deploy on Render

1. Push this repo to GitHub.
2. Render → **New → Web Service** → connect the repo.
   `render.yaml` supplies build/start commands (or set manually:
   build `pip install -r requirements.txt`,
   start `gunicorn server:app --workers 2 --threads 4 --timeout 180 --bind 0.0.0.0:$PORT`).
3. `--timeout 180` matters: worst-case upstream resolve (challenge retries + backoff) runs ~90s.
4. Free plan spins down after ~15 min idle → first request pays a cold start.
   Keep warm with a cron hitting `/api/health` every 10 min.

## Notes

- In-memory cache holds signed URLs until ~4h expiry (per process; lost on cold start).
- Stream proxy allowlists hosts: `testwave.cc`, `pw.live`, `aryavidya.cc`.
