#!/usr/bin/env bash
# Thin wrapper around SimpleArgumentsParser (bash version).
# Just sources the parser, parses $@, and dumps the JSON via `cli print`.

set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
PARSER="$DIR/vendor/simpleargumentsparser/other_languages/bash/parseCLI"

if [ ! -f "$PARSER" ]; then
    echo "error: parser not found at $PARSER" >&2
    echo "       run: git clone --depth 1 https://github.com/stringmanolo/simpleargumentsparser.git vendor/simpleargumentsparser" >&2
    exit 1
fi

source "$PARSER"
parse_cli "$@"
cli print
