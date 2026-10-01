#!/bin/sh
# Every local Markdown link and anchor of the documentation. This is the single
# list of checked inputs: CI and local runs call it.
set -eu
cd "$(dirname "$0")/.."
exec lychee --offline --include-fragments --no-progress \
  README.md AGENTS.md
