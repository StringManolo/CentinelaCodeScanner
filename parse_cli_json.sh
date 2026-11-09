#!/bin/bash
# Thin wrapper around SimpleArgumentsParser (bash version).
# Prints a single JSON object so Python can consume it without Node.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PARSER="$SCRIPT_DIR/vendor/simpleargumentsparser/other_languages/bash/parseCLI"

if [ ! -f "$PARSER" ]; then
    echo "error: parser not found at $PARSER" >&2
    echo "       run: git clone --depth 1 https://github.com/stringmanolo/simpleargumentsparser.git vendor/simpleargumentsparser" >&2
    exit 1
fi

source "$PARSER"
parse_cli "$@"

get_c() {
  local val
  val=$(cli c "$1" 2>/dev/null || true)
  if [ "$val" = "true" ]; then echo "true"
  elif [ -n "$val" ]; then echo "$val"
  else echo ""
  fi
}

get_s() {
  local val
  val=$(cli s "$1" 2>/dev/null || true)
  if [ "$val" = "true" ]; then echo "true"
  elif [ -n "$val" ]; then echo "$val"
  else echo ""
  fi
}

json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\t'/\\t}"
  printf '%s' "$s"
}

PATH_VAL=$(get_c path); [ -z "$PATH_VAL" ] && PATH_VAL=$(get_s p)
MODE_VAL=$(get_c mode)
SERVER_FAST=$(get_c server-fast)
SERVER_PRECISE=$(get_c server-precise)
MODEL_FAST=$(get_c model-fast)
MODEL_PRECISE=$(get_c model-precise)
JSON_OUT=$(get_c json)
NO_DOWNLOAD=$(get_c no-download)

printf '{'
printf '"path":"%s",' "$(json_escape "$PATH_VAL")"
printf '"mode":"%s",' "$(json_escape "$MODE_VAL")"
printf '"server_fast":"%s",' "$(json_escape "$SERVER_FAST")"
printf '"server_precise":"%s",' "$(json_escape "$SERVER_PRECISE")"
printf '"model_fast":"%s",' "$(json_escape "$MODEL_FAST")"
printf '"model_precise":"%s",' "$(json_escape "$MODEL_PRECISE")"
printf '"json_out":"%s",' "$(json_escape "$JSON_OUT")"
printf '"no_download":%s' "$([ "$NO_DOWNLOAD" = "true" ] && echo true || echo false)"
printf '}'
