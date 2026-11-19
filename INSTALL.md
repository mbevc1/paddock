# Installing Paddock

Paddock installs on a fresh AlmaLinux server with one script, `bootstrap.sh`, which prepares the host, installs the `paddock` RPM from the project's dnf repository, and creates the first admin.

Packages are not signed yet (planned as task T2.9), so install Paddock on disposable test machines only.

## Requirements

- **Operating system:** AlmaLinux 9.4 or later, x86_64 or aarch64, freshly installed, with root access.
- **SELinux:** enforcing (the AlmaLinux default).
- **Disk for sites:** `/srv/www` must be its own XFS file system with project quotas, which enforce each vhost's disk limit. Any of these works:
  - a spare disk, partition or LVM volume (`--www-device`), which bootstrap formats when empty;
  - a disk image on the root file system (`--www-file`), loop-mounted; simplest on test machines, with some I/O overhead;
  - a `/srv/www` that is already XFS and mounted with `prjquota`.
- **Free ports:** 80 and 443 for sites and 81 on loopback for internal use, which only Apache or Paddock may hold, and 8443 for the panel and 8080 for its redirect, which only Paddock may hold. Another panel's interface on 8080, such as ISPConfig's, has to go.
- **Panel hostname:** a DNS name that resolves to the server. With a public name, the panel obtains a Let's Encrypt certificate on its own; otherwise it keeps a self-signed one.
- **Network:** outbound HTTPS to GitHub, the AlmaLinux mirrors, EPEL and Remi's repository.

## Install

Fetch the bootstrap script of the latest release, check it and run it:

```bash
BASE=https://github.com/mbevc1/paddock/releases/latest/download
curl -fsSLO $BASE/bootstrap.sh
curl -fsSLO $BASE/SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
sudo bash bootstrap.sh --hostname panel.example.com --www-device /dev/vdb --format
```

At the end it prints the first admin's username, password and TOTP URI, the panel URL and the panel certificate's fingerprint. The password and TOTP URI are shown only once, so store them before closing the terminal.

To install a particular release from the [Releases page](https://github.com/mbevc1/paddock/releases) instead, set `BASE=https://github.com/mbevc1/paddock/releases/download/vX.Y.Z`, replacing `vX.Y.Z` with its tag. Bootstrap always installs the newest `paddock` package from the repository.

Without a spare disk, keep `/srv/www` in a disk image instead, for example 20 GB:

```bash
sudo bash bootstrap.sh --hostname panel.example.com --www-file 20G
```

### Options

| Option | Meaning |
| --- | --- |
| `--hostname NAME` | Panel hostname (required). |
| `--www-device DEV` | Block device for `/srv/www`; needed until `/srv/www` is mounted. |
| `--format` | Create XFS on `--www-device` when it is empty. A device holding a file system is never formatted. |
| `--www-file SIZE` | Keep `/srv/www` in an XFS image of that size, such as `20G`, at `/var/lib/paddock/www.img`, instead of on its own device. Reruns reuse the image. |
| `--email ADDR` | Contact address for Let's Encrypt certificates (optional). |
| `--admin NAME` | Username of the first admin (default `admin`). |
| `--rpm FILE` | Install a local `paddock` RPM instead of the one from the repository. |

### What bootstrap changes

1. Checks the OS, SELinux and root, that no subordinate ID range overlaps the vhost IDs, and that an Apache already installed has a valid configuration.
2. Adds EPEL, Remi's repository (its signing key is pinned in the script) and Paddock's repository, enables MariaDB 10.11, and installs `paddock` and `firewalld`.
3. Checks that the ports above are free.
4. Prepares `/srv/www` with project quotas, on the device or in the image, adds it to `/etc/fstab`, and creates `/srv/jail` for SFTP and shell accounts.
5. Installs host configuration: sshd, sysctl, nftables, fail2ban, MariaDB and front Apache settings. Files containing the line `# paddock: keep` are left alone.
6. Starts MariaDB, opens the firewall ports, and enables `httpd`, `mariadb`, `fail2ban` and the loopback firewall rule.
7. Runs `paddock setup`, which creates Paddock's databases and the first admin, then starts `paddock-agent` and `paddock-web`.

Bootstrap is safe to rerun: it changes only what differs and prints no secrets again.

## First steps

1. **Open the panel** at `https://<hostname>:8443/`. Until the panel has a trusted certificate, compare the certificate's SHA-256 fingerprint with the one bootstrap printed.
2. **Log in as the admin** with the printed password and a code from the printed TOTP URI, added to an authenticator app first. Admin login asks for that code, and admin actions ask for it again. If the URI is lost, `paddock admin totp-reset` gives a new one.
3. **Install PHP** under Admin → PHP, for example 8.3 and 8.4. New vhosts default to 8.3.
4. **Create an owner** under Admin → Owners. The panel shows the owner's password once; pass it on securely. Set the owner's limits there, and require two-factor sign-in if you want it.
5. **As the owner,** change the password and set up two-factor sign-in under Security, then create a vhost under Vhosts with its domain, PHP version and, optionally, an empty database.
6. **Point the domain's DNS** at the server. The front Apache obtains a Let's Encrypt certificate for it once the name resolves.
7. **Upload the site** through an SFTP account added on the vhost's page, into `public/`.

## Upgrade

```bash
sudo dnf upgrade paddock
```

The upgrade restarts `paddock-agent` and `paddock-web`, and database migrations run at start. To apply changed host configuration from a new release, rerun the bootstrap script of that release.

## Uninstall

```bash
sudo dnf remove paddock
```

This stops and removes Paddock's services and its SELinux module but keeps vhosts, their files under `/srv/www`, the databases, `/var/lib/paddock` and the host configuration. Delete vhosts in the panel first if they should go too. A `paddock teardown` command that removes everything is planned but not available yet.

## Administration

Run these as root on the server:

| Command | Purpose |
| --- | --- |
| `paddock admin add NAME` | Add another admin; prints a password and TOTP URI once. |
| `paddock admin totp-reset NAME` | Give an admin a new TOTP secret, for example after losing the phone. |
| `paddock admin login-totp-off NAME` | Let an admin log in with the password alone. Admin actions still ask for a TOTP code, which opens a 10-minute admin window. |
| `paddock admin login-totp-on NAME` | Ask for a TOTP code at the admin's login again, and end the admin's sessions. |
| `paddock admin unlock -for DURATION NAME` | Let an admin run admin actions without a TOTP code for up to 24 hours, for example `-for 8h`. Anyone with the admin's password can act as that admin meanwhile. |
| `paddock admin lock NAME` | End that window early; the next admin action asks for a TOTP code. |
| `paddock admin reset-password NAME` | Set a new password for a panel user and end their sessions. |
| `paddock reconcile -all` | Re-render and re-apply every vhost from Paddock's state. |
| `paddock version` | Print the installed version. |

## Troubleshooting

**Subordinate ID ranges overlap vhost IDs.** Vhost users get UIDs and GIDs from 1000000001 to 1000065535, above the range `useradd` hands out for rootless containers, so this does not happen on a stock system. Bootstrap stops if a user was given a range overlapping those IDs by hand, or if `SUB_UID_MAX` or `SUB_GID_MAX` in `/etc/login.defs` was raised past 1000000000, because such a user could map vhost IDs inside a user namespace. Move the listed ranges below 1000000001 with `usermod --del-subuids`/`--add-subuids` (and the `subgids` equivalents), or lower the setting, then rerun bootstrap.

**The existing Apache configuration is invalid.** Bootstrap runs `apachectl configtest` before changing anything and stops if it fails, for example on a site file that points at a deleted certificate. Fix or remove the file Apache names; it loads only `*.conf` files from `/etc/httpd/conf.d`, so renaming one to `.conf.disabled` turns it off. Then rerun bootstrap.

**A port is in use.** Bootstrap names the port and the program holding it. Stop or reconfigure that program, then rerun bootstrap.

**Logs:**

- Paddock's agent and panel: `journalctl -u paddock-agent -u paddock-web`
- Front Apache: `journalctl -u httpd` and `/var/log/httpd/`
- One vhost's Apache and PHP: `/srv/www/<vhost>/logs/`
- SELinux denials: `ausearch -m avc -ts recent`

## Installing a local build

To install a package built from source instead of a release, build it on an AlmaLinux 9 machine with Go 1.27 and `rpm-build`, then pass it to bootstrap:

```bash
make rpm RPM_VERSION=0.0.1
```

```bash
sudo bash packaging/bootstrap.sh --hostname panel.example.com --www-device /dev/vdb --format --rpm dist/paddock-0.0.1-1.el9.x86_64.rpm
```
