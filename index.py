"""
Security Monitor - aaPanel entry point

aaPanel discovers plugins by importing this file and instantiating
the ``route`` class.  The route dispatcher maps ``request['action']``
to the corresponding method in sec_mon_main.

Typical HTTP flow:
    POST /plugin/sec_mon/index  ->  { action: 'api_events', params: {...} }
    -> route.__call__(request)   ->  sec_mon_main.api_events(params)
    -> JSON string returned to the browser

For page actions (returning HTML):
    { action: 'return_index' }   ->  sec_mon_main.return_index()
    -> HTML string returned to the browser
"""

import json
import os
import sys
import traceback
from typing import Any, Dict

# Ensure plugin root is importable
PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))
if PLUGIN_DIR not in sys.path:
    sys.path.insert(0, PLUGIN_DIR)

from sec_mon_main import sec_mon_main  # noqa: E402
from lib.logger import get_logger  # noqa: E402

log = get_logger("app")


class route:
    """
    aaPanel calls route()(request).  We dispatch to sec_mon_main.<action>.
    """

    def __init__(self) -> None:
        self._app = sec_mon_main()

    def __call__(self, request: dict) -> str:
        """
        Dispatch the incoming *request* dict to the appropriate handler.

        Parameters
        ----------
        request : dict
            Typical shape:
            {
                "action": "api_events",
                "params": {"page": 1, "limit": 50}
            }

        Returns
        -------
        str
            Either an HTML string (for page loaders) or a JSON string
            (for API actions).
        """
        action = request.get("action", "return_index")

        # Security: only allow methods that start with "return_" or "api_"
        if not (action.startswith("return_") or action.startswith("api_")):
            log.warning("Blocked suspicious action: %s", action)
            return json.dumps({"status": -1, "msg": "forbidden"})

        handler = getattr(self._app, action, None)
        if handler is None:
            log.warning("Unknown action requested: %s", action)
            return json.dumps({"status": -1, "msg": f"action not found: {action}"})

        try:
            result = handler(request)
            return result
        except Exception as exc:
            log.error("Unhandled exception in action=%s: %s", action, exc)
            log.error(traceback.format_exc())
            return json.dumps({
                "status": -1,
                "msg": f"internal error: {exc}",
                "data": None,
            })


# =============================================================================
# Standalone CLI runner (for development / debugging outside aaPanel)
# =============================================================================
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

    # Pretty-print if JSON
    try:
        obj = json.loads(output)
        print(json.dumps(obj, indent=2, ensure_ascii=False))
    except (json.JSONDecodeError, TypeError):
        print(output)