import os
import sys

if sys.argv[1:2] == ["fetch-rules"]:
    # Session start. stderr only: a SessionStart hook's stdout goes into
    # Claude's context.
    from boxdawn_guard.rules_bundle import RULES_URL, fetch
    result = fetch(os.environ.get("CLAUDE_PLUGIN_OPTION_API_KEY"), os.environ.get("CLAUDE_PLUGIN_DATA"),
                   url=os.environ.get("BDX_RULES_URL") or RULES_URL)
    print(f"boxdawn guard rules: {result}", file=sys.stderr)
    # The block record goes only on the key the server just accepted, and
    # not at all when the customer keeps it local (plugin setting).
    keep_local = (os.environ.get("CLAUDE_PLUGIN_OPTION_KEEP_BLOCKS_LOCAL") or "").lower() in ("true", "1", "yes")
    if result == "stored" and not keep_local:
        from boxdawn_guard.block_send import BLOCKS_URL, send
        sent = send(os.environ.get("CLAUDE_PLUGIN_OPTION_API_KEY"), os.environ.get("CLAUDE_PLUGIN_DATA"),
                    url=os.environ.get("BDX_BLOCKS_URL") or BLOCKS_URL)
        print(f"boxdawn guard block record: {sent}", file=sys.stderr)
    sys.exit(0)

from boxdawn_guard.command_hook import main

sys.exit(main())
