#!/usr/bin/env bash
# Writes index.html into a dnf repository directory, listing its RPMs newest first, because
# GitHub Pages serves no directory listings.
# Usage: scripts/repo-index.sh DIR TITLE
set -euo pipefail

dir=${1:?usage: repo-index.sh DIR TITLE}
title=${2:?usage: repo-index.sh DIR TITLE}
[[ $title =~ ^[A-Za-z0-9\ ._-]+$ ]] || { echo "unexpected title: $title" >&2; exit 2; }

rows=()
while IFS= read -r name; do
	[[ -n $name ]] || continue
	# Names go into HTML and URLs unescaped, so only plain package file names are listed.
	[[ $name =~ ^[A-Za-z0-9._+-]+\.rpm$ ]] || { echo "unexpected file name: $name" >&2; exit 1; }
	size=$(numfmt --to=iec --suffix=B "$(stat -c %s "$dir/$name")")
	rows+=("<tr><td><a href=\"$name\">$name</a></td><td>$size</td></tr>")
done < <(find "$dir" -maxdepth 1 -name '*.rpm' -printf '%f\n' | sort -V -r)

{
	cat <<HTML
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>$title</title>
<style>
body { font-family: system-ui, sans-serif; margin: 2rem auto; max-width: 48rem; padding: 0 1rem; }
table { border-collapse: collapse; width: 100%; }
td { padding: .3rem .5rem; border-bottom: 1px solid #8884; }
td:last-child { text-align: right; white-space: nowrap; }
</style>
</head>
<body>
<h1>$title</h1>
HTML
	if ((${#rows[@]})); then
		printf '<table>\n'
		printf '%s\n' "${rows[@]}"
		printf '</table>\n'
	else
		printf '<p>No packages yet.</p>\n'
	fi
	printf '<p><a href="repodata/repomd.xml">Repository metadata</a> · <a href="../../">Paddock</a></p>\n</body>\n</html>\n'
} >"$dir/index.html"
