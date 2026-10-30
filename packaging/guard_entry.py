import os
import sys

if sys.argv[1:2] == ["fetch-rules"]:
    # Session start. stderr only: a SessionStart hook's stdout goes into
    # Claude's context.
    from boxdawn_guard.rules_bundle import RULES_URL, fetch
    result = fetch(os.environ.get("CLAUDE_PLUGIN_OPTION_API_KEY"), os.environ.get("CLAUDE_PLUGIN_DATA"),
                   url=os.environ.get("BDX_RULES_URL") or RULES_URL)
    print(f"boxdawn guard rules: {result}", file=sys.stderr)
    sys.exit(0)

from boxdawn_guard.command_hook import main

sys.exit(main())
