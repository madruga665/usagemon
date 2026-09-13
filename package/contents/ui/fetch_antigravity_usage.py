#!/usr/bin/env python3
"""Fetch quota data from the `agy` CLI's embedded local HTTP/HTTPS server or cache.

`agy` (the Antigravity CLI) exposes its quota endpoint while an interactive
session is alive, requiring a CSRF token.
This script:
  1. Checks for live session data from the status-line hook or local session cache.
  2. Queries an already-running `agy` process for the current user using its
     loopback address/port and CSRF token.
  3. Otherwise launches a short-lived `agy` session in a pty, captures the live
     quota from the startup sequence or memory, and tears it down immediately.
  4. Falls back to recent cached statusline or agy-hud quota data if offline.

Privacy: this never touches Google/Antigravity account credentials — it only
talks to 127.0.0.1 over the loopback port `agy` opens. TLS verification is
skipped for loopback only.
On any problem this always prints valid JSON and exits 0, so the widget never hangs.
"""
import glob
import json
import os
import pty
import re
import shutil
import signal
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request

QUOTA_PATH = "/exa.language_server_pb.LanguageServerService/RetrieveUserQuotaSummary"
STATUSLINE_QUOTA_FILE = os.path.expanduser("~/.cache/usagemon/statusline_quota.json")
SESSION_CACHE_FILE = os.path.expanduser("~/.cache/usagemon/session.json")
AGY_HUD_CACHE_FILE = os.path.expanduser("~/.cache/agy-hud/quota_cache.json")
STARTUP_TIMEOUT = 4.0
POLL_INTERVAL = 0.2
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


def emit_error(message):
    print(json.dumps({"error": {"message": message}}))


def find_binary():
    override = os.environ.get("ANTIGRAVITY_CLI_PATH")
    if override and os.path.isfile(override) and os.access(override, os.X_OK):
        return override
    found = shutil.which("agy")
    if found:
        return found
    for candidate in (
        os.path.expanduser("~/.local/bin/agy"),
        "/opt/homebrew/bin/agy",
        "/usr/local/bin/agy",
    ):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def quota_from_statusline_payload(max_age_seconds=None):
    if not os.path.isfile(STATUSLINE_QUOTA_FILE):
        return None
    try:
        if max_age_seconds is not None:
            mtime = os.path.getmtime(STATUSLINE_QUOTA_FILE)
            if time.time() - mtime > max_age_seconds:
                return None

        with open(STATUSLINE_QUOTA_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        q = data.get("quota")
        if not isinstance(q, dict):
            return None

        groups = []
        g_buckets = []
        if "gemini-weekly" in q:
            b = q["gemini-weekly"]
            g_buckets.append({
                "bucketId": "gemini-weekly",
                "window": "weekly",
                "remainingFraction": b.get("remaining_fraction", 1.0),
                "resetTime": b.get("reset_time", ""),
            })
        if "gemini-5h" in q:
            b = q["gemini-5h"]
            g_buckets.append({
                "bucketId": "gemini-5h",
                "window": "5h",
                "remainingFraction": b.get("remaining_fraction", 1.0),
                "resetTime": b.get("reset_time", ""),
            })
        if g_buckets:
            groups.append({
                "displayName": "Gemini Models",
                "buckets": g_buckets
            })

        p_buckets = []
        if "3p-weekly" in q:
            b = q["3p-weekly"]
            p_buckets.append({
                "bucketId": "3p-weekly",
                "window": "weekly",
                "remainingFraction": b.get("remaining_fraction", 1.0),
                "resetTime": b.get("reset_time", ""),
            })
        if "3p-5h" in q:
            b = q["3p-5h"]
            p_buckets.append({
                "bucketId": "3p-5h",
                "window": "5h",
                "remainingFraction": b.get("remaining_fraction", 1.0),
                "resetTime": b.get("reset_time", ""),
            })
        if p_buckets:
            groups.append({
                "displayName": "Claude and GPT models",
                "buckets": p_buckets
            })

        if groups:
            return {"groups": groups}
    except Exception:
        pass
    return None


def load_cached_session():
    if not os.path.isfile(SESSION_CACHE_FILE):
        return None, None
    try:
        with open(SESSION_CACHE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        tok = data.get("csrf_token")
        addr = data.get("ls_address")
        if tok and UUID_RE.match(tok):
            return tok, addr
    except Exception:
        pass
    return None, None


def save_cached_session(token, addr):
    if not token or not addr:
        return
    try:
        os.makedirs(os.path.dirname(SESSION_CACHE_FILE), exist_ok=True)
        tmp = f"{SESSION_CACHE_FILE}.tmp.{os.getpid()}"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({
                "csrf_token": token,
                "ls_address": addr,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }, f)
        os.replace(tmp, SESSION_CACHE_FILE)
    except Exception:
        pass


def extract_tokens_from_proc():
    """Scan /proc for running processes that have CSRF tokens in environ or cmdline."""
    candidates = []
    seen = set()

    for p in glob.glob("/proc/[0-9]*/environ"):
        try:
            with open(p, "rb") as f:
                data = f.read()
            if b"ANTIGRAVITY_CSRF_TOKEN=" in data:
                tok = None
                addr = None
                for item in data.split(b"\0"):
                    if item.startswith(b"ANTIGRAVITY_CSRF_TOKEN="):
                        val = item[23:].decode("ascii", "ignore").strip()
                        if UUID_RE.match(val):
                            tok = val
                    elif item.startswith(b"ANTIGRAVITY_LS_ADDRESS="):
                        val = item[23:].decode("ascii", "ignore").strip()
                        if ":" in val:
                            addr = val
                if tok and (tok, addr) not in seen:
                    seen.add((tok, addr))
                    candidates.append((tok, addr))
        except Exception:
            continue

    for p in glob.glob("/proc/[0-9]*/cmdline"):
        try:
            with open(p, "rb") as f:
                raw = f.read()
            if b"csrf_token" in raw:
                parts = [x.decode("ascii", "ignore") for x in raw.split(b"\0")]
                tok = None
                port = None
                for i, arg in enumerate(parts):
                    if arg in ("--csrf_token", "--csrf-token") and i + 1 < len(parts):
                        cand = parts[i + 1].strip()
                        if UUID_RE.match(cand):
                            tok = cand
                    elif arg.startswith("--csrf_token="):
                        cand = arg.split("=", 1)[1].strip()
                        if UUID_RE.match(cand):
                            tok = cand
                    elif arg in ("--port", "-p") and i + 1 < len(parts):
                        port = parts[i + 1].strip()
                    elif arg.startswith("--port="):
                        port = arg.split("=", 1)[1].strip()
                if tok:
                    addr = f"127.0.0.1:{port}" if port else None
                    if (tok, addr) not in seen:
                        seen.add((tok, addr))
                        candidates.append((tok, addr))
        except Exception:
            continue

    return candidates


def listening_ports(pid):
    ports = []
    # Fast path: ss (typically ~10-30ms, no docker/overlay permission warnings)
    try:
        out = subprocess.run(
            ["ss", "-tlnp", "-H"],
            capture_output=True, text=True, timeout=1.0,
        ).stdout
        pid_needle = f"pid={pid},"
        for line in out.splitlines():
            if pid_needle in line:
                m = re.search(r"(?:127\.0\.0\.1|localhost|\*|\[::1\]):(\d+)", line)
                if m:
                    p = int(m.group(1))
                    if p not in ports:
                        ports.append(p)
        if ports:
            return ports
    except Exception:
        pass

    # Fallback: lsof
    try:
        out = subprocess.run(
            ["lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-a", "-p", str(pid)],
            capture_output=True, text=True, timeout=1.5,
        ).stdout
        for line in out.splitlines()[1:]:
            m = re.search(r"(?:127\.0\.0\.1|localhost|\*|\[::1\]):(\d+)\s*\(LISTEN\)", line)
            if m:
                p = int(m.group(1))
                if p not in ports:
                    ports.append(p)
    except Exception:
        pass
    return ports


def query_endpoint(port_or_addr, token=None):
    if not port_or_addr:
        return None
    s = str(port_or_addr).strip()
    if ":" in s:
        host, port = s.split(":", 1)
        if host in ("localhost", "0.0.0.0", "*"):
            host = "127.0.0.1"
    else:
        host = "127.0.0.1"
        port = s

    headers = {
        "Content-Type": "application/json",
        "Connect-Protocol-Version": "1",
    }
    if token:
        headers["X-Codeium-Csrf-Token"] = token

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for proto in ("http", "https"):
        url = f"{proto}://{host}:{port}{QUOTA_PATH}"
        req = urllib.request.Request(url, data=b"{}", headers=headers, method="POST")
        ssl_ctx = ctx if proto == "https" else None
        try:
            with urllib.request.urlopen(req, timeout=1.5, context=ssl_ctx) as resp:
                body = resp.read()
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
            continue
        try:
            data = json.loads(body)
        except ValueError:
            continue
        if isinstance(data, dict):
            if isinstance(data.get("response"), dict):
                return data["response"]
            if isinstance(data.get("groups"), list):
                return data
    return None


def existing_pids():
    pids = []
    uid = str(os.getuid())
    for cmd in (["pgrep", "-u", uid, "-x", "agy"], ["pgrep", "-u", uid, "-f", "language_server"]):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=2).stdout
            for p in out.split():
                if p.isdigit():
                    val = int(p)
                    if val != os.getpid() and val not in pids:
                        pids.append(val)
        except Exception:
            pass
    return pids


def try_existing():
    # 1. Direct query using active cached session (very fast: ~5-10ms)
    cache_tok, cache_addr = load_cached_session()
    if cache_tok and cache_addr:
        quota = query_endpoint(cache_addr, cache_tok)
        if quota is not None:
            return quota

    # 2. Check fresh statusline payload (updated continuously by agy statusline hook)
    fresh_statusline = quota_from_statusline_payload(max_age_seconds=300)
    if fresh_statusline is not None:
        return fresh_statusline

    # 3. Check environment
    candidates = []
    env_tok = os.environ.get("ANTIGRAVITY_CSRF_TOKEN")
    env_addr = os.environ.get("ANTIGRAVITY_LS_ADDRESS")
    if env_tok and UUID_RE.match(env_tok):
        candidates.append((env_tok, env_addr))

    if cache_tok:
        candidates.append((cache_tok, cache_addr))

    # 4. Scan /proc for live processes
    proc_candidates = extract_tokens_from_proc()
    for item in proc_candidates:
        if item not in candidates:
            candidates.append(item)

    for tok, addr in candidates:
        if addr:
            quota = query_endpoint(addr, tok)
            if quota is not None:
                save_cached_session(tok, addr)
                return quota

    # 5. Scan listening ports of running agy / language_server processes
    pids = existing_pids()
    tokens_to_try = [tok for tok, _ in candidates if tok]
    tokens_to_try.append(None)

    for pid in pids:
        for port in listening_ports(pid):
            for tok in tokens_to_try:
                quota = query_endpoint(port, tok)
                if quota is not None:
                    save_cached_session(tok, f"127.0.0.1:{port}")
                    return quota

    return None


def quota_from_agy_hud_cache():
    if not os.path.isfile(AGY_HUD_CACHE_FILE):
        return None
    try:
        with open(AGY_HUD_CACHE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        models = data.get("models", {})
        if not models:
            return None

        gemini_buckets = []
        p3_buckets = []
        for name, info in models.items():
            if not isinstance(info, dict):
                continue
            rem = info.get("remainingFraction", 1.0)
            rst = info.get("resetTime")
            if "gemini" in name.lower():
                gemini_buckets.append((rem, rst))
            else:
                p3_buckets.append((rem, rst))

        groups = []
        if gemini_buckets:
            gemini_buckets.sort(key=lambda x: x[0])
            groups.append({
                "displayName": "Gemini Models",
                "buckets": [
                    {
                        "bucketId": "gemini-5h",
                        "window": "5h",
                        "remainingFraction": gemini_buckets[0][0],
                        "resetTime": gemini_buckets[0][1],
                    }
                ]
            })
        if p3_buckets:
            p3_buckets.sort(key=lambda x: x[0])
            groups.append({
                "displayName": "Claude and GPT models",
                "buckets": [
                    {
                        "bucketId": "3p-5h",
                        "window": "5h",
                        "remainingFraction": p3_buckets[0][0],
                        "resetTime": p3_buckets[0][1],
                    }
                ]
            })
        if groups:
            return {"groups": groups}
    except Exception:
        pass
    return None


def main():
    # 1. Try to query a live running agy session or recent statusline hook update
    quota = try_existing()

    # 2. If no live session is running (e.g. system boot or idle), use persistent caches
    #    so the widget always loads immediately without hanging or spawning background CLI sessions
    if quota is None:
        quota = quota_from_statusline_payload()

    if quota is None:
        quota = quota_from_agy_hud_cache()

    if quota is None:
        emit_error("Antigravity quota unavailable. Open agy to initialize.")
        return

    print(json.dumps(quota))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        emit_error(f"agy fetch failed: {e}")
