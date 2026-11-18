# Phase 0 results

Fill in each row after running the script on a fresh VM (see `poc/README.md`). Paste the `FAIL` lines and SELinux denials under the task, and update `docs/plan.md` part 1 where a result changes the design.

## Environment

| Item | Value |
| --- | --- |
| Date | |
| AlmaLinux version | |
| Kernel | |
| systemd | |
| httpd | |
| MariaDB | |
| PHP 8.3 / 8.4 (Remi) | |
| VM provider, CPUs, memory | |

## Results

| Task | Script | Result | Notes |
| --- | --- | --- | --- |
| T0.1 VM baseline | `00-setup.sh` | not run | |
| T0.2 Sandbox visibility | `02-sandbox.sh` | not run | |
| T0.3 Backend Apache | `03-backend.sh` | not run | |
| T0.4 Remi FPM label and switch | `04-fpm-switch.sh` | not run | |
| T0.5 MariaDB from the sandbox | `05-mariadb.sh` | not run | |
| T0.6 Loopback rule | `06-loopback.sh` | not run | |
| T0.7 SFTP jail | `07-sftp.sh` | not run | |
| T0.8 Shell jail | `08-shell.sh` | not run | |
| T0.9 Kernel settings | `09-sysctl.sh` | not run | |
| T0.10 PHP application | `10-php-app.sh` | not run | |
| T0.11 Scale | `11-scale.sh` | not run | |
| T0.12 Red team | `90-redteam.sh` | not run | |

## T0.11 measurements

| Measurement | Value |
| --- | --- |
| Vhosts | |
| Memory per idle vhost | |
| Time to start all units | |
| Boot to all units active | |
| `systemctl daemon-reload` with all vhosts | |

## Open design questions

Raised while writing the scripts; each needs a VM result before part 1 changes.

1. **Backend runtime directory (§7.2).** The backend config sets no `DefaultRuntimeDir`, so httpd would keep mutexes and sockets under `/run/httpd`, which the vhost user cannot write. The PoC adds `DefaultRuntimeDir /run/paddock-httpd/<id>`; T0.3 shows whether the spec needs it.
2. **`combined` log format (§7.2).** `CustomLog ... combined` refers to a nickname that `httpd.conf` defines. The backend config loads no `httpd.conf`, so the PoC defines the format itself.
3. **Subordinate ID ranges (§5, §7.7).** EL 9 gives each regular user a subordinate range starting at 100000, the same range as vhost UIDs. A user holding such a range (for example `vagrant`) could map vhost UIDs inside a user namespace; `user.max_user_namespaces = 0` blocks that today. The PoC creates vhost users without ranges; `90-redteam.sh` fails while any range overlaps 100001 to 165535. Options: move vhost UIDs above the subordinate pool, or have `bootstrap.sh` refuse or rewrite overlapping ranges.
4. **Owner slice hierarchy (§5, §7.1).** systemd reads dashes in slice names as nesting, so `paddock-owner-3.slice` sits under `paddock.slice/paddock-owner.slice/`. That works and gives a single `paddock.slice` to measure, but should be stated in the spec.
5. **PHP switch and the shared socket path (§8).** Both FPM masters bind the same socket path. When the old master stops it may unlink the path the new master now owns. T0.4 checks that the socket survives and that no request fails.
6. **`php-fpm -t` as root (invariant 6).** The config has no pool `user`, so `php-fpm -t` refuses to run as root; the agent must run it as the vhost user.
7. **SFTP account names (§4, §5, §7.5).** `ChrootDirectory /srv/jail/%u` ties the login name to the vhost ID, yet `max_access_accounts` allows several accounts. The PoC logs in as the vhost user. Several accounts per vhost need either names that map to the jail (for example `ChrootDirectory` per `Match User`) or one jail per account.
8. **nftables restarts (§7.6).** `nft -f` on the original §7.6 file appended a second rule on every load. The file now declares and deletes its table before defining it, so each load replaces the table in one transaction; a load that fails leaves the old rule in force. 06-loopback.sh checks both.
9. **Shell jail `php` (§7.5).** The jail's `/usr` is a read-only bind, so the `php` link lives in `/opt/paddock/bin` inside the jail, with `PATH` set in the jail's `/etc/profile`. T0.8 shows whether Remi's `php` runs from there without the SCL `enable` script.
10. **Long requests behind two proxies.** Front and backend Apache both defaulted to a 60 s proxy timeout, so a slow request could time out while PHP kept running. Decided: the timeouts nest, 300 s in PHP-FPM, 305 s in the backend, 310 s in the front (§7.4); a render test keeps them in order. The PoC scripts keep the defaults.
11. **`MDNotifyCmd` user (§10, T1.12).** `front.md-renewed` accepts only root. If mod_md runs `MDNotifyCmd` as `apache`, the agent must also accept the `apache` UID for that one operation.
12. **`md-status` layout and exposure (§10, T1.12).** The reader looks fields up leniently because the JSON layout varies between mod_md releases; record the VM's actual output. `Require local` also lets tenant PHP read `md-status` on loopback, which lists every managed domain on the server.
