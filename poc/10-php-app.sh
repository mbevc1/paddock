#!/usr/bin/env bash
# T0.10 A PHP application in vhost A behind the front proxy: it writes its own files, keeps
# sessions, stays inside open_basedir, and sees HTTPS.
source "$(dirname "$0")/lib.sh"
poc_start
install_unit_templates

readonly DOMAIN=app.test

FRONT=1 vh_create 1 1 8.3 "$DOMAIN"
on_cleanup "remove_owner_slice 1"
id=$(vh_id 1)
pub=$WWW/$id/public

front() { curl -sk -m 30 --resolve "$DOMAIN:443:127.0.0.1" "$@" "https://$DOMAIN$1"; }

cat >"$pub/app.php" <<'PHP'
<?php
switch ($_GET['a'] ?? '') {
case 'write':
    $ok = file_put_contents(__DIR__ . '/../private/state.txt', 'v1') !== false
        && file_put_contents(__DIR__ . '/../private/state.txt', 'v2') !== false;
    echo $ok ? file_get_contents(__DIR__ . '/../private/state.txt') : 'ERR';
    break;
case 'outside':
    echo @file_put_contents('/tmp/escape.txt', 'x') === false ? 'BLOCKED' : 'WROTE';
    break;
case 'session':
    session_start();
    $_SESSION['n'] = ($_SESSION['n'] ?? 0) + 1;
    echo $_SESSION['n'];
    break;
case 'https':
    echo ($_SERVER['HTTPS'] ?? '') === 'on' ? 'https' : 'http';
    break;
}
PHP
chown "$id:$id" "$pub/app.php"

check "PHP writes and updates files in its tree" test "$(front '/app.php?a=write')" = v2
check "files PHP writes belong to $id" test "$(stat -c %U "$WWW/$id/private/state.txt")" = "$id"
check "open_basedir stops writes outside the tree" test "$(front '/app.php?a=outside')" = BLOCKED
jar=$POC_TMP/cookies
check "first request starts a session" test "$(front '/app.php?a=session' -c "$jar" -b "$jar")" = 1
check "the session persists" test "$(front '/app.php?a=session' -c "$jar" -b "$jar")" = 2
check "session files stay in the vhost tree" bash -c "ls '$WWW/$id/sessions' | grep -q '^sess_'"
check "PHP sees HTTPS behind the front proxy" test "$(front '/app.php?a=https')" = https
