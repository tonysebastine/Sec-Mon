"""
Security Monitor - aaPanel entry point

Dispatches incoming requests to the appropriate handler in sec_mon_main.
Includes CSRF token handling to satisfy aaPanel 8.0.3 security checks.
"""

import json
import os
import sys
import traceback
from typing import Any, Dict

# Ensure the plugin root is on sys.path
PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))
if PLUGIN_DIR not in sys.path:
    sys.path.insert(0, PLUGIN_DIR)

from sec_mon_main import sec_mon_main  # noqa: E402
from lib.logger import get_logger  # noqa: E402

log = get_logger("app")


def _extract_csrf_token(args: dict) -> str:
    """
    Extract the CSRF token from the aaPanel request envelope.

    aaPanel stores the token in:
      - args['request_csrf_token']  (the request body field)
      - args['s']                    (short alias used by some plugins)
      - args['csrf_token']           (some versions)
      - the session cookie (handled by aaPanel's middleware before us)
    """
    return (
        args.get("request_csrf_token", "")
        or args.get("s", "")
        or args.get("csrf_token", "")
    )


def _embed_csrf(response_str: str, csrf: str) -> str:
    """
    Embed the CSRF token in the JSON response so aaPanel's CSRF
    middleware sees it and accepts the response.
    """
    if not csrf:
        return response_str
    try:
        obj = json.loads(response_str)
        if isinstance(obj, dict):
            obj["csrf_token"] = csrf
            return json.dumps(obj, ensure_ascii=False, default=str)
    except Exception:
        pass
    return response_str


class route:
    """aaPanel calls route()(request).  Dispatch to sec_mon_main.<action>."""

    def __init__(self) -> None:
        self._app = sec_mon_main()

    def __call__(self, request: dict) -> str:
        action = request.get("action", "return_index")
        csrf = _extract_csrf_token(request)

        # Security: only allow whitelisted action prefixes
        if not (action.startswith("return_") or action.startswith("api_")):
            log.warning("Blocked suspicious action: %s", action)
            return json.dumps({
                "status": -1,
                "msg": "forbidden",
                "csrf_token": csrf,
            })

        handler = getattr(self._app, action, None)
        if handler is None:
            log.warning("Unknown action requested: %s", action)
            return json.dumps({
                "status": -1,
                "msg": f"action not found: {action}",
                "csrf_token": csrf,
            })

        try:
            result = handler(request)
            return _embed_csrf(result, csrf)
        except Exception as exc:
            log.error("Unhandled exception in action=%s: %s", action, exc)
            log.error(traceback.format_exc())
            return json.dumps({
                "status": -1,
                "msg": f"internal error: {exc}",
                "data": None,
                "csrf_token": csrf,
            })


# -----------------------------------------------------------------------------
# Standalone CLI runner (for development / debugging outside aaPanel)
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Security Monitor - CLI test runner")
    parser.add_argument("action", nargs="?", default="api_status",
                        help="Action name (e.g. api_status, api_events, api_ping)")
    parser.add_argument("--json-params", dest="params", default="{}",
                        help="JSON params to pass, e.g. '{\"page\":1}'")
    args = parser.parse_args()

    try:
        params = json.loads(args.params)
    except json.JSONDecodeError:
        params = {}

    request = {"action": args.action, "params": params}
    r = route()
    output = r(request)

    try:
        obj = json.loads(output)
        print(json.dumps(obj, indent=2, ensure_ascii=False))
    except (json.JSONDecodeError, TypeError):
        print(output)