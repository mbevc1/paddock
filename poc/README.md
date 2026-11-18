# Phase 0 proof of concept

Throwaway scripts that check the design in `docs/plan.md` part 1 on a real AlmaLinux 9.4+ VM. They change the host as root: run them only on a disposable VM, never on a workstation.

Each script prints one `PASS`/`FAIL` line per check, ends with `RESULT PASS` or `RESULT FAIL`, exits non-zero on failure, and removes what it created. On failure it also prints the SELinux denials logged during the run. Record results in `docs/poc-results.md`.

## VM

```bash
cd poc
vagrant up                      # box almalinux/9, second disk at /dev/vdb (libvirt) or /dev/sdb (VirtualBox)
vagrant ssh -c 'sudo /vagrant/poc/00-setup.sh --device /dev/vdb --format'
vagrant snapshot save clean
```

`POC_MEMORY`, `POC_CPUS`, and `POC_WWW_DISK_GB` size the VM. Without `--device`, `00-setup.sh` puts `/srv/www` on an XFS loop file instead.

## Scripts

| Script | Task | Checks |
| --- | --- | --- |
| `00-setup.sh` | T0.1 | packages from BaseOS/AppStream, EPEL, Remi; `/srv/www` with project quotas; MariaDB `unix_socket` for root |
| `02-sandbox.sh` | T0.2 | §7.1 drop-in: private `/srv/www`, `/run/paddock`, `/tmp`, `/dev/shm`, process list |
| `03-backend.sh` | T0.3 | §7.2 backend Apache as the vhost user in `httpd_t`; module file names |
| `04-fpm-switch.sh` | T0.4 | Remi FPM label; §8 PHP switch under a 1 req/s loop |
| `05-mariadb.sh` | T0.5 | §9 `unix_socket` login from the sandbox; grant escaping |
| `06-loopback.sh` | T0.6 | §7.6 nftables rule, including after `firewall-cmd --reload` |
| `07-sftp.sh` | T0.7 | §7.5 SFTP chroot and forwarding limited to `127.0.0.1:3306` |
| `08-shell.sh` | T0.8 | §7.5 shell jail, private procfs, masked `user@`, user slice |
| `09-sysctl.sh` | T0.9 | §7.6 kernel settings, then reruns 02 to 08 |
| `10-php-app.sh` | T0.10 | PHP application writing its own files, `open_basedir`, sessions, HTTPS detection |
| `11-scale.sh` | T0.11 | `create [COUNT]`, reboot, `report`, `cleanup` |
| `90-redteam.sh` | T0.12 | every attempt from §7.7 |

Run them in order after `00-setup.sh`, for example `sudo /vagrant/poc/02-sandbox.sh`. Revert to the `clean` snapshot between runs when a script aborts halfway.

## Where the PoC departs from part 1

- The backend Apache config adds `DefaultRuntimeDir` and the `combined` `LogFormat`; it loads no `httpd.conf`, which otherwise defines both.
- Front vhosts use the `mod_ssl` self-signed certificate instead of `MDomain`: test VMs have no public DNS for ACME.
- `useradd` runs with `-K SUB_UID_COUNT=0 -K SUB_GID_COUNT=0` and an explicit group, so vhost users get no subordinate ID ranges and their GID equals their UID.
- The nftables file declares and deletes its table before defining it, so `nft -f` replaces the table atomically; `paddock-nft.service` reloads it without a gap.
- Unit templates are written to `/etc/systemd/system`; the RPM installs the backend template to `/usr/lib/systemd/system` later.
