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
# A session opened before an update runs this script again from the older
# plugin folder. It must not put its older build over a newer one, so a build
# in place with a strictly newer VERSION is left alone.
ver_gt() {  # $1 is strictly newer than $2, both N.N.N
  case "$1$2" in *[!0-9.]*) return 1 ;; esac
  old_ifs=$IFS; IFS=.; set -- $1 $2; IFS=$old_ifs
  [ $# -eq 6 ] || return 1
  [ "$1" -gt "$4" ] || { [ "$1" -eq "$4" ] && { [ "$2" -gt "$5" ] || { [ "$2" -eq "$5" ] && [ "$3" -gt "$6" ]; }; }; }
}
keep=0
if [ -f "$src/VERSION" ] && [ -f "$dst/VERSION" ] && [ -x "$dst/bdxguard.exe" ] \
    && ver_gt "$(cat "$dst/VERSION")" "$(cat "$src/VERSION")"; then
  keep=1
fi
if [ "$keep" -eq 0 ] && ! { [ -f "$dst/BUILD_ID" ] && cmp -s "$src/BUILD_ID" "$dst/BUILD_ID"; }; then
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
fi
# With an API key in the plugin's settings, fetch the signed rules in the
# background (the session does not wait). Without one this does nothing and
# opens no connection.
if [ -n "${CLAUDE_PLUGIN_OPTION_API_KEY:-}" ]; then
  nohup "$dst/bdxguard.exe" fetch-rules </dev/null >/dev/null 2>&1 &
fi
