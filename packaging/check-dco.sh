#!/bin/sh
# Every commit in a git range must carry a Signed-off-by line of its author
# (CONTRIBUTING.md). Merge commits are skipped.
#
#   packaging/check-dco.sh origin/main..HEAD
set -eu

range=${1:?usage: check-dco.sh <git range>}
bad=0
for c in $(git rev-list --no-merges "$range"); do
	author=$(git show -s --format='%an <%ae>' "$c")
	if ! git show -s --format='%(trailers:key=Signed-off-by,valueonly)' "$c" | grep -qxF "$author"; then
		echo "::error::$(git show -s --format='%h %s' "$c"): no 'Signed-off-by: $author'"
		bad=1
	fi
done
if [ "$bad" -ne 0 ]; then
	echo "Add the line with: git commit --amend -s --no-edit (see CONTRIBUTING.md)" >&2
	exit 1
fi
echo "check-dco.sh: every commit in $range is signed off"
