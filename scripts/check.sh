#!/bin/sh
# Mechanical gate run by CI and local checks. Every check that a change must pass
# before review is listed here and nowhere else; a new crate, device target or test
# suite is added to this script in the change that introduces it.
set -eu
cd "$(dirname "$0")/.."

scripts/check-links.sh
