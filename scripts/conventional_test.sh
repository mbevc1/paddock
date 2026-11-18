#!/usr/bin/env bash
# Tests scripts/conventional.sh.
set -uo pipefail
cd "$(dirname "$0")" || exit

failures=0
check() {
	local want=$1 kind=$2 subject=$3 got
	printf '%s\n' "$subject" | ./conventional.sh "$kind" >/dev/null
	got=$?
	if [[ $got -ne $want ]]; then
		echo "FAIL: $kind '$subject' exited $got, want $want"
		failures=$((failures + 1))
	fi
}

for s in "feat(agent): add vhost directory creation" "fix(deploy)!: reload the loopback rule atomically" \
	"ci: add Dependabot, labels and a PR labeler" "build(deps): bump the go-dependencies group with 2 updates" \
	"ci(deps): bump actions/checkout from 7.0.1 to 7.1.0" "docs: explain PHP 8.4 support" \
	"feat(web): a summary long enough to pass the format but warn about its length, nothing more"; do
	check 0 title "$s"
	check 0 commit "$s"
done
for s in "Add Dependabot config" "feature: add something" "feat: Add capitalised summary" \
	"feat(Agent): uppercase scope" "feat:missing space" "fix: " "" "T1.4 Add vhost directory creation" \
	"Revert \"feat: add x\""; do
	check 1 title "$s"
	check 1 commit "$s"
done
check 0 commit "Merge branch 'main' into 20261117_dependabot"
check 1 title "Merge branch 'main' into 20261117_dependabot"

# Every line is checked: one bad subject among good ones fails the run.
if printf 'feat: add a\nnot conventional\nfix: b\n' | ./conventional.sh commit >/dev/null; then
	echo "FAIL: a bad subject among good ones passed"
	failures=$((failures + 1))
fi
if [[ $(printf 'feat(web): %s\n' "$(printf 'x%.0s' {1..70})" | ./conventional.sh title) != *"::warning"* ]]; then
	echo "FAIL: no warning for a long subject"
	failures=$((failures + 1))
fi
./conventional.sh </dev/null >/dev/null 2>&1
[[ $? -eq 2 ]] || {
	echo "FAIL: a missing kind is not a usage error"
	failures=$((failures + 1))
}

if [[ $failures -gt 0 ]]; then
	echo "conventional_test: $failures failures"
	exit 1
fi
echo "conventional_test: ok"
