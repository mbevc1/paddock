#!/usr/bin/env bash
# Checks that each line on stdin is a Conventional Commits subject as CLAUDE.md defines it, and
# prints GitHub annotations for the ones that are not.
# Usage: conventional.sh title|commit <subjects
#   commit also accepts the merge commits GitHub creates when a branch is updated.
set -euo pipefail

kind=${1:-}
[[ $kind == title || $kind == commit ]] || {
	echo "usage: conventional.sh title|commit <subjects" >&2
	exit 2
}

readonly TYPES='feat|fix|docs|test|refactor|perf|build|ci|chore|revert'
readonly MAX=72
readonly FORMAT="^($TYPES)(\([a-z0-9._/-]+\))?!?: [^[:space:]]"

failed=0
while IFS= read -r subject || [[ -n $subject ]]; do
	if [[ $kind == commit && $subject == "Merge "* ]]; then
		continue
	fi
	if [[ ! $subject =~ $FORMAT ]]; then
		echo "::error title=$kind::'$subject' is not 'type(scope): summary' with type one of ${TYPES//|/, }."
		failed=1
		continue
	fi
	summary=${subject#*: }
	if [[ ${summary:0:1} =~ [[:upper:]] ]]; then
		echo "::error title=$kind::start the summary in lowercase: '$subject'."
		failed=1
		continue
	fi
	if ((${#subject} >= MAX)); then
		echo "::warning title=$kind::'$subject' has ${#subject} characters; subjects stay under $MAX."
	fi
done
exit "$failed"
