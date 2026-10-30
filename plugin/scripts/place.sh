#!/bin/sh
# SessionStart: put this machine's guard build at
# ${CLAUDE_PLUGIN_DATA}/current/bdxguard.exe, the one path the PreToolUse hook
# runs on every OS (Unix ignores the extension). Until it is there, the hook
# fails to start and onFailure "block" stops the Bash call.
set -eu
case "$(uname -s)" in
  Darwin) os=macos ;;
  Linux) os=linux ;;
  *) exit 0 ;;  # Windows, including Git Bash: place.ps1 does it
esac
case "$(uname -m)" in
  arm64|aarch64) arch=arm64 ;;
  x86_64|amd64) arch=x64 ;;
  *) echo "boxdawn guard: no build for $(uname -m)" >&2; exit 1 ;;
esac
src="$CLAUDE_PLUGIN_ROOT/dist/$os-$arch"
dst="$CLAUDE_PLUGIN_DATA/current"
[ -d "$src" ] || { echo "boxdawn guard: no build for $os-$arch" >&2; exit 1; }
if [ -f "$dst/BUILD_ID" ] && cmp -s "$src/BUILD_ID" "$dst/BUILD_ID"; then exit 0; fi
mkdir -p "$CLAUDE_PLUGIN_DATA"
tmp="$CLAUDE_PLUGIN_DATA/current.tmp.$$"
rm -rf "$tmp"
cp -R "$src" "$tmp"
mv "$tmp/bdxguard" "$tmp/bdxguard.exe"
chmod +x "$tmp/bdxguard.exe"
rm -rf "$dst.old"
if [ -d "$dst" ]; then mv "$dst" "$dst.old"; fi
mv "$tmp" "$dst"
rm -rf "$dst.old"
