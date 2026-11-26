#!/usr/bin/env python3
import base64
import json
import os
import sys
import urllib.error
import urllib.request


def error(message):
    print(json.dumps({"error": {"message": message}}))
    sys.exit(0)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)


def account_id(tokens):
    value = tokens.get("account_id") or tokens.get("accountId")
    if value:
        return value
    id_token = tokens.get("id_token") or tokens.get("idToken") or ""
    parts = id_token.split(".")
    if len(parts) < 2:
        return ""
    try:
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
        auth = claims.get("https://api.openai.com/auth") or {}
        return auth.get("chatgpt_account_id") or ""
    except Exception:
        return ""


def main():
    path = os.environ.get("CODEX_AUTH") or os.path.join(os.path.expanduser("~"), ".codex", "auth.json")
    try:
        with open(path) as handle:
            auth = json.load(handle)
    except Exception:
        error("Could not read ~/.codex/auth.json. Log in with codex login first.")

    tokens = auth.get("tokens") or {}
    token = tokens.get("access_token") or tokens.get("accessToken") or ""
    if not token:
        error("No Codex access token found. Log in with codex login first.")

    headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}
    account = account_id(tokens)
    if account:
        headers["ChatGPT-Account-Id"] = account

    request = urllib.request.Request("https://chatgpt.com/backend-api/wham/usage", headers=headers)
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(request, timeout=10) as response:
            body = response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            error("Codex login expired. Run codex login again.")
        error("Codex usage API returned HTTP %d." % exc.code)
    except Exception:
        error("Could not reach the Codex usage API.")

    try:
        json.loads(body)
    except Exception:
        error("Invalid response from the Codex usage API.")

    sys.stdout.write(body)
    if not body.endswith("\n"):
        sys.stdout.write("\n")


if __name__ == "__main__":
    main()
