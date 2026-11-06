#!/bin/sh
# Prints the Homebrew cask for a built package:
#
#   packaging/macos/render-cask.sh 1.2.3 dist/macos/latchwire-1.2.3.pkg >latchwire.rb
set -eu

[ $# -eq 2 ] || { echo "usage: render-cask.sh <version> <pkg>" >&2; exit 2; }
[ -f "$2" ] || { echo "render-cask.sh: no such file: $2" >&2; exit 1; }

sum=$(shasum -a 256 "$2" | cut -d' ' -f1)
sed -e "s/@VERSION@/$1/" -e "s/@SHA256@/$sum/" "$(dirname "$0")/latchwire.rb.in"
