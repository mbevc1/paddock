# Paddock plan

Part 1 is the specification; part 2 is the task list. Where the specification states exact paths, names, or settings, use them as written. Where it says "verify on the VM", confirm the detail during phase 0 and update part 1.

Work through the tasks in part 2 in order. Tick a task's checkbox when every acceptance criterion passes and note deferred items under it. Section numbers (§) refer to part 1.

# Part 1: Specification


## 1. Scope

**In scope:** isolated vhosts, owners with limits, PHP version per vhost (switchable in place), MariaDB databases, SFTP and opt-in SSH, TLS per vhost, one web panel for admins and owners, in-app notifications, one-script install.

**Out of scope:** DNS, email hosting, reseller accounts, containers.

**Target workload:** custom PHP applications (Laravel, Symfony, plain PHP). Paddock provides isolated hosting environments; it installs no application.

**Sources:** AlmaLinux BaseOS/AppStream (including dnf modules), EPEL, and Remi for parallel PHP versions. Nothing else.

## 2. Host stack

| Component | Source | Use |
| --- | --- | --- |
| Apache httpd 2.4, `event` MPM | AppStream | front instance (TLS, `mod_md`, proxy) plus one backend instance per vhost |
| `mod_md` | AppStream | ACME for customer vhosts, front only |
| PHP-FPM 8.2, 8.3, 8.4 | Remi (`phpNN-php-fpm`) | one FPM master per vhost |
| MariaDB 10.11 | AppStream module `mariadb:10.11` | databases |
| OpenSSH | BaseOS | SFTP and shell jails |
| fail2ban | EPEL | sshd bans |
| SELinux | BaseOS | enforcing |
| firewalld, nftables | BaseOS | ports and loopback rule |
| XFS project quotas | BaseOS | disk limits per vhost |
| systemd 252 | BaseOS | sandboxed units, owner slices |

## 3. Processes and sockets

| Process | User | Listens on | Purpose |
| --- | --- | --- | --- |
| `paddock agent` | root | `/run/paddock/agent.sock` (`root:paddock`, `0660`) | all host changes |
| `paddock web` | `paddock` | `:8443` TLS, `:8080` redirect, `/run/paddock/acme/acme.sock` | panel, API, ACME challenge responses |
| front `httpd` | `apache` | `:80`, `:443`, `127.0.0.1:81` (root only) | TLS for vhosts, proxy to backends; `md-status` for the agent on port 81 |
| `paddock-httpd@vNNNNN` | vhost user | `127.64.X.Y:81` | static files, `.htaccess`, PHP via FastCGI |
| `paddock-phpNN-fpm@vNNNNN` | vhost user | `/run/paddock/fpm/vNNNNN/php.sock` (`0600`) | PHP |

The agent accepts connections only from UID 0 and the UID of user `paddock` (checked with `SO_PEERCRED`).

## 4. Agent protocol

Newline-delimited JSON over the Unix socket, one request and one response per line.

```json
{"id":"r1","op":"vhost.create","actor":{"user_id":7,"role":"owner","owner_id":12},"admin_totp":"","args":{...}}
{"id":"r1","ok":true,"result":{...}}
{"id":"r1","ok":false,"error":{"code":"limit_exceeded","message":"vhost limit reached (5)"}}
```

- `actor` is recorded in the audit log. The agent re-checks ownership and limits itself; it never trusts `role` or `owner_id` for authorization beyond scoping.
- Operations marked **admin** require `admin_totp`. The agent verifies it against the admin's TOTP secret in `state.db`, rejects reuse of a code, and then opens a 10-minute admin window for that admin user ID.
- **Admin identity lives in the agent.** `state.db` holds the list of admin user IDs and their TOTP secrets; `web.db` never stores an admin's TOTP secret. Admins are created, and their TOTP reset, only with root CLI commands (`paddock admin add`, `paddock admin totp-reset`). A web process that marks an owner as admin in `web.db` gains nothing, because the agent does not know that user as an admin.
- Operations marked **gate** verify a credential and open a window; they are callable by the web process for any user ID.
- Operations marked **system** are callable only by the web process itself, not on behalf of a user.
- Error codes: `invalid_argument`, `not_found`, `forbidden`, `limit_exceeded`, `conflict`, `totp_required`, `totp_invalid`, `apply_failed`, `internal`.
- Long-running operations return `{"job_id":...}`; progress is polled with `job.get`.

### Operations

| Op | Class | Arguments |
| --- | --- | --- |
| `owner.create`, `owner.update`, `owner.delete` | admin | name, limits |
| `owner.limits.set` | admin | owner_id, limits |
| `php.version.install`, `php.version.remove` | admin | version (`8.2`, `8.3`, `8.4`) |
| `vhost.create` | owner | owner_id, primary domain, aliases, php version |
| `vhost.update` | owner | vhost_id, aliases, php settings |
| `vhost.php.switch` | owner | vhost_id, version |
| `vhost.delete` | owner | vhost_id, confirm |
| `vhost.suspend`, `vhost.resume` | admin | vhost_id |
| `db.create`, `db.delete` | owner | vhost_id, suffix |
| `dbuser.create`, `dbuser.delete`, `dbuser.password.reset` | owner | vhost_id, name suffix, grants |
| `access.create`, `access.delete` | owner | vhost_id, kind (`sftp`, `shell`), password or keys |
| `access.key.add`, `access.key.remove` | owner | account, public key |
| `cert.status`, `cert.upload` | owner | vhost_id, PEM chain and key |
| `pma.session.create` | owner | vhost_id, database |
| `usage.get` | owner | vhost_id or owner_id |
| `job.get` | owner | job_id |
| `events.list` | system | since cursor; returns agent events (applies, failures, quota, certificates) for the web process to turn into notifications |
| `reconcile.all` | admin | none |
| `admin.totp.verify` | gate | user_id, code; also used as the admin's second factor at login |

## 5. Identifiers

| Thing | Rule | Example |
| --- | --- | --- |
| Vhost number N | 1 to 65535, allocated sequentially, never reused | 12 |
| Vhost ID and Linux user | `v` + N zero-padded to 5 digits | `v00012` |
| UID and GID | 1000000000 + N | 1000000012 |
| Backend address | `127.64.(N >> 8).(N & 255)`, port 81 | `127.64.0.12:81` |
| XFS project ID | N | 12 |
| Owner slice | `paddock-owner-<owner_id>.slice` | `paddock-owner-3.slice` |
| Database name | `<vhost id>_<suffix>`, suffix `^[a-z0-9]{1,20}$`, total ≤ 32 | `v00012_app` |
| Primary DB user | the vhost ID | `v00012` |
| Extra DB user | `<vhost id>_<suffix>`, suffix `^[a-z0-9]{1,8}$` | `v00012_ro` |

Usernames are never derived from domains.

**Owner limits** (stored in `limits`, enforced by the agent):

| Limit | Applies to | Default |
| --- | --- | --- |
| `max_vhosts` | number of vhosts | 5 |
| `disk_mb` | XFS usage of all vhosts plus database sizes | 10240 |
| `max_databases` | databases across all vhosts | 10 |
| `max_db_users` | extra DB users across all vhosts | 10 |
| `max_access_accounts` | SFTP and shell accounts | 5 |
| `shell_allowed` | whether shell accounts may be created | false |
| `php_versions` | versions the owner may choose | all installed |
| `memory_max_mb`, `cpu_quota_pct`, `tasks_max` | owner slice | 2048, 200, 512 |
| `pm_max_children` | per vhost FPM pool | 10 |
| `max_user_connections` | per DB user | 20 |

## 6. Filesystem layout

```
/srv/www/                       root:root        0711   own LV, XFS, mounted prjquota
/srv/www/v00012/                v00012:v00012    0700   vhost home, XFS project 12
  public/  private/  logs/  tmp/  sessions/              all v00012:v00012 0700 (public 0750)
/srv/jail/v00012/               root:root        0755   SFTP/SSH chroot
  site/                         bind mount of /srv/www/v00012
/run/paddock/                   root:root        0755   agent.sock
/run/paddock/acme/              paddock:paddock  0755   acme.sock (panel ACME challenges)
/run/paddock/fpm/v00012/        v00012:v00012    0700
/etc/paddock/httpd/v00012.conf  root:root        0644   backend Apache config
/etc/paddock/fpm/v00012.conf    root:root        0644   FPM config
/etc/httpd/conf.d/paddock-v00012.conf                   front vhost
/var/lib/paddock/               root:root        0755
/var/lib/paddock/agent/         root:root        0700   state.db, archive/
/var/lib/paddock/web/           paddock:paddock  0700   web.db, acme/ (panel certificate cache), panel key
/var/backups/paddock/           root:root        0700   backups (phase 2)
```

SELinux: `semanage fcontext -a -t httpd_sys_rw_content_t '/srv/www(/.*)?'`, then `restorecon`. The `paddock` module (`deploy/selinux/paddock.cil`) labels `/run/paddock/acme` `httpd_var_run_t` and lets `httpd_t` connect to the challenge socket.

## 7. Rendered files

Templates live in `internal/render/templates/`. The values below are the reference output for vhost `v00012`, owner 3, PHP 8.3, domain `shop.example.com`.

### 7.1 Unit templates

`/usr/lib/systemd/system/paddock-httpd@.service` (shipped in the RPM):

```ini
[Unit]
Description=Paddock backend Apache for %i
After=network.target

[Service]
Type=notify
User=%i
Group=%i
ExecStart=/usr/sbin/httpd -DFOREGROUND -f /etc/paddock/httpd/%i.conf
ExecReload=/usr/sbin/httpd -f /etc/paddock/httpd/%i.conf -k graceful
RuntimeDirectory=paddock-httpd/%i
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

`/etc/systemd/system/paddock-php83-fpm@.service` (written by the agent, one per installed PHP version):

```ini
[Unit]
Description=Paddock PHP 8.3 FPM for %i

[Service]
Type=notify
User=%i
Group=%i
ExecStart=/opt/remi/php83/root/usr/sbin/php-fpm --nodaemonize --fpm-config /etc/paddock/fpm/%i.conf
ExecReload=/bin/kill -USR2 $MAINPID
CapabilityBoundingSet=
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Shared sandbox drop-in, written for each unit instance of the vhost (`paddock-httpd@v00012.service.d/10-sandbox.conf`, `paddock-php83-fpm@v00012.service.d/10-sandbox.conf`, and the vhost's timers):

```ini
[Service]
Slice=paddock-owner-3.slice
TemporaryFileSystem=/srv/www /srv/jail /run/paddock
BindPaths=/srv/www/v00012 /run/paddock/fpm/v00012
ReadWritePaths=/srv/www/v00012 /run/paddock/fpm/v00012
ProtectProc=invisible
ProcSubset=pid
PrivateTmp=yes
PrivateIPC=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
NoNewPrivileges=yes
RestrictSUIDSGID=yes
```

Owner slice `/etc/systemd/system/paddock-owner-3.slice`:

```ini
[Slice]
MemoryMax=2G
CPUQuota=200%
TasksMax=512
```

### 7.2 Backend Apache config

`/etc/paddock/httpd/v00012.conf`. Load an explicit minimal module set with `LoadModule` lines (mpm_event, unixd, systemd, authz_core, authz_host, authn_core, authn_file, auth_basic, authz_user, access_compat, alias, dir, mime, log_config, setenvif, env, headers, expires, deflate, filter, rewrite, remoteip, proxy, proxy_fcgi). Verify module file names on the VM.

```apache
ServerRoot /etc/httpd
Listen 127.64.0.12:81
PidFile /run/paddock-httpd/v00012/httpd.pid
ErrorLog /srv/www/v00012/logs/error.log
CustomLog /srv/www/v00012/logs/access.log combined
TypesConfig /etc/mime.types
ServerName shop.example.com
DocumentRoot /srv/www/v00012/public
DirectoryIndex index.php index.html

RemoteIPHeader X-Forwarded-For
RemoteIPTrustedProxy 127.0.0.1
SetEnvIf X-Forwarded-Proto https HTTPS=on

<Directory />
    AllowOverride None
    Require all denied
</Directory>
<Directory /srv/www/v00012/public>
    Options SymLinksIfOwnerMatch
    AllowOverride AuthConfig FileInfo Indexes Limit Options=Indexes,SymLinksIfOwnerMatch
    Require all granted
</Directory>
ProxyTimeout 305
<FilesMatch "\.php$">
    SetHandler "proxy:unix:/run/paddock/fpm/v00012/php.sock|fcgi://localhost"
</FilesMatch>
```

No `User` or `Group` directives; the unit already runs as the vhost user.

### 7.3 PHP-FPM config

`/etc/paddock/fpm/v00012.conf`:

```ini
[global]
error_log = /srv/www/v00012/logs/php-fpm.log
systemd_interval = 10

[v00012]
listen = /run/paddock/fpm/v00012/php.sock
listen.mode = 0600
pm = ondemand
pm.max_children = 10
pm.process_idle_timeout = 30s
pm.max_requests = 500
request_terminate_timeout = 300s
php_admin_value[open_basedir] = /srv/www/v00012/
php_admin_value[upload_tmp_dir] = /srv/www/v00012/tmp
php_admin_value[sys_temp_dir] = /srv/www/v00012/tmp
php_admin_value[session.save_path] = /srv/www/v00012/sessions
php_admin_value[error_log] = /srv/www/v00012/logs/php-error.log
php_admin_value[pdo_mysql.default_socket] = /var/lib/mysql/mysql.sock
php_admin_value[mysqli.default_socket] = /var/lib/mysql/mysql.sock
php_admin_value[opcache.jit] = off
env[DB_HOST] = localhost
env[DB_SOCKET] = /var/lib/mysql/mysql.sock
env[DB_USER] = v00012
```

`pm.max_children` and memory settings come from the vhost's limits.

### 7.4 Front Apache vhost

`/etc/httpd/conf.d/paddock-v00012.conf`:

```apache
MDomain shop.example.com www.shop.example.com
MDRequireHttps permanent

<VirtualHost *:80>
    ServerName shop.example.com
    ServerAlias www.shop.example.com
</VirtualHost>

<VirtualHost *:443>
    ServerName shop.example.com
    ServerAlias www.shop.example.com
    SSLEngine on
    ProxyPreserveHost On
    RequestHeader set X-Forwarded-Proto https
    ProxyPass        / http://127.64.0.12:81/ timeout=310
    ProxyPassReverse / http://127.64.0.12:81/
</VirtualHost>
```

Request timeouts nest so the innermost layer ends a slow request first: PHP-FPM stops a script after 300 s of wall-clock time (`request_terminate_timeout`; PHP's own `max_execution_time` counts only CPU time), the backend waits 305 s for FPM (`ProxyTimeout`), and the front waits 310 s for the backend (`timeout=` on `ProxyPass`). A visitor whose request runs out of time gets a 504 only once PHP has already stopped, never while it keeps running.

Global front settings in `/etc/httpd/conf.d/paddock-00-global.conf`: `MDContactEmail`, `MDNotifyCmd /usr/bin/paddock agent-notify md-renewed`, `AllowOverride None` everywhere, no `DocumentRoot` under `/srv/www`, `mod_status` disabled. Uploaded custom certificates replace `MDomain` with `SSLCertificateFile` and `SSLCertificateKeyFile` stored under `/etc/pki/paddock/`.

Panel hostname on port 80:

```apache
<VirtualHost *:80>
    ServerName panel.example.com
    ProxyPass /.well-known/acme-challenge/ "unix:/run/paddock/acme/acme.sock|http://panel/.well-known/acme-challenge/"
    RedirectMatch 301 ^/(?!\.well-known/acme-challenge/)(.*)$ https://panel.example.com:8443/$1
</VirtualHost>
```

### 7.5 Jails and SSH

Mount unit for the SFTP jail, `srv-jail-v00012-site.mount` (name from `systemd-escape --path`):

```ini
[Mount]
What=/srv/www/v00012
Where=/srv/jail/v00012/site
Type=none
Options=bind

[Install]
WantedBy=multi-user.target
```

Shell jails add bind mounts of `/usr` and `/opt/remi` with `ro,nosuid,nodev`, symlinks `bin`, `sbin`, `lib`, `lib64` into `usr/`, a generated `etc/` (only this user in `passwd` and `group`, `resolv.conf`, `pki/`), a minimal `dev/` (`null`, `zero`, `urandom`, `tty`), `tmp/` (`1777`), and `proc/` mounted with `-t proc -o hidepid=invisible,subset=pid`. `php` in the jail points at the vhost's current PHP version.

`/etc/ssh/sshd_config.d/50-paddock.conf`:

```
AuthorizedKeysFile /etc/ssh/authorized_keys/%u

Match Group paddock-sftp,paddock-shell
    ChrootDirectory /srv/jail/%u
    AllowTcpForwarding local
    PermitOpen 127.0.0.1:3306
    X11Forwarding no
    AllowAgentForwarding no

Match Group paddock-sftp
    ForceCommand internal-sftp -d /site
```

For every vhost user: `systemctl mask user@<uid>.service`, and a `user-<uid>.slice.d/limits.conf` drop-in matching the owner's limits.

### 7.6 Firewall and kernel

`/etc/paddock/nftables.conf`, loaded by `paddock-nft.service` (oneshot, `After=firewalld.service`; `systemctl reload` loads a changed file):

```
# Declaring and deleting the table first makes nft -f replace it in one transaction: the old
# rule stays in force until the new one is in place, and a file that fails to load changes nothing.
table inet paddock
delete table inet paddock

table inet paddock {
    chain output {
        type filter hook output priority 0; policy accept;
        ip daddr 127.64.0.0/16 tcp dport 81 meta skuid != "apache" reject
        ip daddr 127.0.0.1 tcp dport 81 meta skuid != "root" reject
    }
}
```

`/etc/sysctl.d/90-paddock.conf`:

```
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
user.max_user_namespaces = 0
```

### 7.7 Isolation guarantees

A process or login of vhost A must not read, write, list, signal, or connect to anything belonging to vhost B. Phase 0 (T0.12) and the integration suite (T1.27) try every row.

| Attempt from vhost A against vhost B | Blocked by |
| --- | --- |
| Read B's files | `0700` trees owned by B; B's tree absent from A's mount namespace |
| Make a shared web server read B's files (symlink, alias, rewrite) | no shared reader: A's backend runs as A; the front Apache reads no tenant files |
| Run code as B through B's PHP socket | socket `0600` owned by B, path hidden from A |
| Connect to B's backend on loopback | nftables: only the `apache` UID may connect to `127.64.0.0/16` port 81 |
| Squat B's backend address while it restarts | port 81 is below 1024; only units with `CAP_NET_BIND_SERVICE` can bind it |
| List or inspect B's processes | `ProtectProc=invisible`, `ProcSubset=pid`, private procfs in shell jails; cross-UID ptrace denied |
| Read B's temp files, shared memory, IPC | `PrivateTmp`, `PrivateDevices`, `PrivateIPC`, private `tmp/` in jails |
| Read B's databases | MariaDB grants per vhost user; `unix_socket` checks the caller's UID |
| See B through SFTP or a shell | chroot jail containing only A's tree and a generated `/etc` |
| Starve B of CPU, memory, disk | owner slices, user slices, XFS project quotas |
| Gain privileges | `NoNewPrivileges`, `RestrictSUIDSGID`; jail mounts are `nosuid`, so setuid binaries under `/usr` gain nothing |

Known limits: a kernel exploit crosses every boundary; SELinux confines Apache and PHP as a whole but labels all tenants alike.

## 8. Vhost lifecycle

**Create:** allocate N; `useradd -u UID -U -M -d /srv/www/vNNNNN -s /sbin/nologin vNNNNN`; create directories; set XFS project and limit; `restorecon`; render backend, FPM, front, drop-ins, slice; create jail and mount unit; `systemctl daemon-reload`; start FPM, then backend; `apachectl configtest` and graceful reload of the front; create primary DB user. Roll back every step on failure.

**PHP switch:** render FPM config for the new version (same socket path), start `paddock-phpNEW-fpm@vNNNNN`, wait for the socket, stop and disable the old unit, update the shell jail's `php` link, record the version.

**Delete:** stop and disable units, unmount and remove the jail, remove front config and reload, drop databases and DB users, archive the tree to `/var/lib/paddock/agent/archive/` for 7 days, remove the Linux user, release the XFS project. N is never reused.

**Suspend:** stop units and make the front vhost return 503.

## 9. MariaDB

- Socket `/var/lib/mysql/mysql.sock`, `bind-address=127.0.0.1`, port 3306 closed in firewalld.
- The agent connects as `root@localhost` via `unix_socket`; the installer verifies this in `mysql.global_priv`.
- Primary DB user: `CREATE USER 'v00012'@'localhost' IDENTIFIED VIA unix_socket OR mysql_native_password USING PASSWORD('<random>')`.
- Grants: `GRANT ALL ON \`v00012\_app\`.* TO 'v00012'@'localhost'`. Escape `_` and `%` in database names in grants. Reject database names whose escaped form exceeds 64 characters.
- `MAX_USER_CONNECTIONS` per user from limits.
- Quota: database sizes count toward the owner's disk; at 90 % notify, at 100 % revoke `INSERT`, `UPDATE`, `CREATE`, keep `SELECT`, `DELETE`.
- Backups: `mariadb-dump --single-transaction` per database next to the vhost's file backup.

## 10. TLS

- **Vhosts:** `mod_md` in the front Apache. `MDNotifyCmd` calls the agent, which runs `apachectl configtest` and a graceful reload. The agent reads `md-status` for expiry notifications from a front listener on `127.0.0.1:81`, which the §7.6 rule keeps to root: the page lists every managed domain, so tenants must not read it.
- **Panel:** at install, a self-signed ECDSA P-256 certificate for the hostname and server IP; the SHA-256 fingerprint is printed. The web process then obtains a Let's Encrypt certificate with `golang.org/x/crypto/acme` using HTTP-01 only, served through `/run/paddock/acme/acme.sock`, which the front Apache reaches through the `paddock` SELinux module (`deploy/selinux/paddock.cil`). `GetCertificate` returns the Let's Encrypt certificate for SNI matches and the self-signed one otherwise. HSTS once a trusted certificate is active.

## 11. Panel

### 11.1 Roles

| Permission | Admin | Owner |
| --- | --- | --- |
| Manage owners and limits | yes | no |
| Install or remove PHP versions | yes | no |
| Server settings, reconcile | yes | no |
| Impersonate an owner | yes | no |
| Suspend or resume vhosts | yes | no |
| Create, update, delete own vhosts | yes | yes, within limits |
| Switch PHP version of own vhosts | yes | yes, installed versions only |
| Databases, DB users, access accounts, keys | yes | yes, own vhosts |
| Upload certificates | yes | yes, own vhosts |
| phpMyAdmin sign-on | yes | yes, own databases |
| API tokens | yes | yes, scoped to own rights |

Collaborators are phase 3.

### 11.2 Authentication

- Local accounts: Argon2id (64 MiB, 3 iterations, parallelism 1, 16-byte salt, 32-byte key; parameters stored with the hash, rehash on login when they change). Minimum 12 characters, checked against an embedded list of common passwords. Unknown usernames still run one hash.
- TOTP: RFC 6238, SHA-1, 6 digits, 30 s, ±1 step, used codes rejected. Owners' secrets live in `web.db`; admins' secrets live only in `state.db` and the web process checks an admin's code through `admin.totp.verify`. Mandatory for admins, optional for owners (admins can require it per owner). Ten single-use recovery codes for owners, stored hashed; admin recovery is `paddock admin totp-reset` as root.
- OIDC (phase 2): authorization code with PKCE (S256), `state`, `nonce`; verify signature via JWKS, `iss`, `aud`, `exp`; link by `iss` + `sub`; optional `hd` check for Google.
- GitHub (phase 2): OAuth2 with PKCE and `state`; identity = numeric `id` from `GET /user`; verified emails from `GET /user/emails`; access token discarded.
- Linking only from the profile page or through an invitation; never by matching email alone.

### 11.3 Sessions and requests

- Session token: 32 random bytes, stored as SHA-256 in `web.db`. Cookie `__Host-pd_session`, `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`.
- Owners: 30 min idle, 12 h absolute. Admins: 15 min idle, 12 h absolute. Rotate the token on login and privilege change.
- State-changing requests: `Origin` must equal the panel origin, plus a per-session CSRF token (form field or `X-CSRF-Token` header).
- Rate limiting per IP and per account with exponential backoff (1 s doubling to 15 min).
- Step-up (re-enter password or TOTP if the last check is older than 5 min): password, email, MFA changes, SSH keys, access accounts, deletions, API tokens.
- Headers: `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'`, `X-Frame-Options: DENY`, `Referrer-Policy: same-origin`, `X-Content-Type-Options: nosniff`.

### 11.4 UI

Server-rendered `html/template` pages with htmx for partial updates. Every route registers a permission; templates render actions with `{{if .Can "perm"}}`. Resources load through owner-scoped queries, so foreign IDs return 404. Notifications stream over Server-Sent Events.

Pages: login, TOTP, dashboard, vhost list, vhost detail (domains, PHP version, settings, logs), databases, DB users, access accounts and keys, certificates, notifications, profile and security, API tokens; admin: owners, limits, PHP versions, server status, audit log.

### 11.5 Notifications

Stored in `web.db`, delivered over SSE; optional SMTP relay and webhook forwarding. Triggers: certificate failure or expiry within 14 days, quota at 90 %, failed apply, new SSH key, login from a new IP, PHP version nearing end of life, pending PHP updates (admins), new phpMyAdmin release.

## 12. phpMyAdmin (phase 2)

Signed release tarball unpacked to `/usr/share/paddock/phpmyadmin`, served as a vhost `db.<panel hostname>` running as Linux user `paddock-pma` with its own backend and FPM units. `auth_type = signon`: the panel asks the agent for a temporary DB user with the same grants (2 h expiry), passes a single-use 30 s token, and `signon.php` redeems it from the web process over a local socket. `AllowRoot = false`, `AllowNoPassword = false`.

## 13. Data model

**state.db (agent, root only):** `owners`, `limits`, `vhosts` (n, id, owner_id, uid, php_version, status), `domains`, `databases`, `db_users`, `access_accounts`, `ssh_keys`, `certs`, `php_versions`, `admins` (user_id, username, totp_secret, last_used_step, window_until), `jobs`, `audit` (time, actor, op, args without secrets, result).

**web.db (web, user paddock):** `users` (id, username, role, owner_id, password_hash, totp_secret for owners only, disabled), `recovery_codes`, `identities` (user_id, issuer, subject), `sessions` (token_hash, user_id, created, last_seen, ip, user_agent, mfa_at), `api_tokens`, `invitations`, `notifications`, `login_events`.

Both use numbered SQL migrations embedded in the binary and applied at start.

## 14. Packaging and installation

Paddock ships as an RPM from a dnf repository hosted on the project's GitHub Pages. Packages are unsigned for now; signing is task T2.9 and must be done before production use. A short bootstrap script prepares repositories, installs the RPM, and configures the host; `paddock setup`, compiled into the binary, creates Paddock's databases and first admin. Upgrades are `dnf upgrade paddock`.

### 14.1 Build and publish (GitHub only)

Everything is hosted in the GitHub repository `github.com/<owner>/paddock`: source, releases, and the dnf repository. No other server is needed. The repository must be public so dnf and the bootstrap can fetch without credentials.

- **Trigger:** pushing a tag `vX.Y.Z` runs `.github/workflows/release.yaml`.
- **Build:** the workflow runs in the `almalinux:9` container image (containers at build time only; servers never run them). It builds `CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$VERSION" ./cmd/paddock` for `x86_64` and `aarch64`; templates, migrations, and web assets are embedded, so the binary is the only artifact. `rpmbuild` turns it into RPMs using `packaging/paddock.spec`.
- **Signing:** none for now (see T2.9). Integrity rests on HTTPS from GitHub and on `SHA256SUMS`.
- **GitHub Release:** attaches the RPMs, `bootstrap.sh`, and `SHA256SUMS`.
- **dnf repository on GitHub Pages:** the site also carries a landing page with install instructions. The workflow downloads the RPMs of the last five releases, runs `createrepo_c`, and deploys the result with `actions/deploy-pages`. Pages sites are limited to 1 GB, which is why only five releases stay in the repository; older RPMs remain on the Releases page.
- **Resulting URLs:**
    - Repository: `https://<owner>.github.io/paddock/el$releasever/$basearch/` (the workflow publishes `el9/` and, once supported, `el10/`)
    - Release assets: `https://github.com/<owner>/paddock/releases/download/vX.Y.Z/<file>`
- **What unsigned means:** anyone who gains write access to the GitHub repository or its Actions can publish an RPM that servers install as root on their next `dnf upgrade paddock`. Acceptable for development and test VMs; not for production.

### 14.2 RPM contents

| Path | Purpose |
| --- | --- |
| `/usr/bin/paddock` | the binary |
| `/usr/lib/systemd/system/paddock-agent.service`, `paddock-web.service`, `paddock-nft.service` | Paddock services |
| `/usr/lib/systemd/system/paddock-httpd@.service` | backend Apache template |
| `/usr/lib/sysusers.d/paddock.conf` | user `paddock`, groups `paddock-sftp`, `paddock-shell` |
| `/usr/lib/tmpfiles.d/paddock.conf` | `/run/paddock`, `/run/paddock/acme` and `/run/paddock/fpm` |
| `/usr/share/selinux/packages/paddock.cil` | SELinux module, installed by `%post`: labels `/run/paddock/acme` and lets the front Apache connect to the challenge socket |
| `/usr/share/paddock/etc/` | default configs that `bootstrap.sh` installs into `/etc` at the same relative paths: sshd drop-in, sysctl, nftables, fail2ban jail, MariaDB, front Apache global config, panel port 80 vhost |
| `/var/lib/paddock/`, `agent/`, `web/` | state directories with the owners and modes from §6 (`%dir`) |

Per-version FPM unit templates (`paddock-phpNN-fpm@.service`) are written by the agent when a PHP version is installed, since the set of versions differs per server.

RPM dependencies: `httpd mod_ssl mod_md mariadb-server fail2ban nftables xfsprogs policycoreutils-python-utils openssh-server`, plus `policycoreutils` and `selinux-policy-targeted` for the scriptlets. Scriptlets use `%sysusers_create_compat`, `%systemd_post`, `%systemd_preun`, and `%systemd_postun_with_restart` for `paddock-agent` and `paddock-web`; `%post` loads the `paddock` SELinux module with `semodule`, and erasing the package removes it. The RPM never changes sshd, sysctl, firewall, or Apache settings itself; `bootstrap.sh` does that explicitly.

### 14.3 Bootstrap script

`bootstrap.sh` is a release asset, fetched for a specific version:

```
VER=v0.1.0
BASE=https://github.com/<owner>/paddock/releases/download/$VER
curl -fsSLO $BASE/bootstrap.sh
curl -fsSLO $BASE/SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
sudo bash bootstrap.sh --hostname panel.example.com --www-device /dev/vdb --format
```

Options: `--hostname` (required), `--www-device` (needed until `/srv/www` is mounted), `--format` (create XFS on an empty device), `--www-file` (keep `/srv/www` in an XFS image of the given size at `/var/lib/paddock/www.img`, loop-mounted, instead of on a device), `--email` (ACME contact, optional), `--admin` (first admin's username, default `admin`), `--rpm` (install a local Paddock RPM instead of the repository, for testing a build before it is released). Rerunning the script is safe; it changes nothing that is already in place.

1. Check OS (EL 9.4+), SELinux enforcing, root. Refuse subordinate ID ranges in `/etc/subuid` or `/etc/subgid` that overlap the vhost IDs 1000000001 to 1000065535, since their holder could map vhost UIDs in a user namespace if `user.max_user_namespaces` were ever raised, and refuse a `SUB_UID_MAX` or `SUB_GID_MAX` in `/etc/login.defs` at or above 1000000001, which would let `useradd` hand out such a range later. Vhost IDs lie above the default pool (`SUB_UID_MAX` 600100000), so neither happens on a stock system. If Apache is already installed, refuse to start while `apachectl configtest` fails, before anything on the host changes.
2. `dnf install epel-release`; install `remi-release-9` after checking its GPG key fingerprint against the value pinned in the script (EPEL and Remi packages stay signature-checked).
3. On EL 9 only: `dnf module enable mariadb:10.11` (EL 10 ships MariaDB 10.11 as a plain package).
4. Write `/etc/yum.repos.d/paddock.repo` with `baseurl=https://<owner>.github.io/paddock/el$releasever/$basearch/`, `gpgcheck=0`, `repo_gpgcheck=0`, and a comment pointing to T2.9.
5. `dnf install paddock`.
6. Check free ports: 80, 81 and 443 may be held only by `httpd` or `paddock`, 8080 and 8443 only by `paddock`.
7. Prepare `/srv/www` on the given XFS device with `prjquota` (format only if empty and confirmed with `--format`; never one holding a filesystem), or in the `--www-file` image (created once, never reformatted); create `/srv/www` (`0711`) and `/srv/jail` (`0755`); add the `semanage fcontext` rule and `restorecon`. Refuse a `/srv/www` holding anything but the `.paddock` marker and vhost directories.
8. Install `/usr/share/paddock/etc/` into `/etc`, keeping files that contain `# paddock: keep`; fill the panel hostname into `paddock-01-panel.conf`; write `MDContactEmail` to `/etc/httpd/conf.d/paddock-00-contact.conf` when `--email` is given; write `/etc/paddock/web.env` (`PADDOCK_HOSTNAME`, `PADDOCK_ACME_EMAIL`); comment out `mod_status` in `00-base.conf`; load the sysctl settings.
9. Start MariaDB and verify `unix_socket` for root in `mysql.global_priv`.
10. Open firewalld ports 80, 443, 8080, 8443; enable `paddock-nft`, `fail2ban`, `httpd`, `mariadb`; reload Apache after `apachectl configtest` and sshd after `sshd -t`.
11. `paddock setup --admin NAME`.
12. Enable and start `paddock-agent` and `paddock-web`; print the panel URL and the panel certificate fingerprint that `paddock-web` logs at first start.

### 14.4 `paddock setup`

Runs as root, idempotent. It creates `state.db` and `web.db` (migrations included, `web.db` owned by `paddock`) and, on the first run only, the first admin: a random password in `web.db` and a TOTP secret in `state.db`. It prints the username, password, and TOTP URI once; later runs find an admin and print nothing secret. It changes nothing else: `bootstrap.sh` prepares the host, `paddock web` creates its self-signed certificate at first start, and the admin installs PHP versions from the panel.

### 14.5 Upgrade and removal

- `dnf upgrade paddock` replaces the binary; `%systemd_postun_with_restart` restarts agent and web; migrations run at start; the agent re-renders changed templates on its next reconcile.
- `dnf remove paddock` stops and removes Paddock's services but leaves vhosts, data, and `/var/lib/paddock` in place. `paddock teardown --yes` (run before removal) deletes all vhosts and Paddock's host configuration.

### 14.6 Test VM

Use a disposable AlmaLinux 9.4+ VM with a second disk for `/srv/www`, for example the `almalinux/9` Vagrant box or the AlmaLinux generic cloud image with cloud-init. Snapshot it right after first boot so every test run starts clean.

## 15. Defaults for open decisions

Use these until told otherwise; each is a setting, not a code path.

- **New owners:** SFTP only; shell accounts need `shell_allowed` set by an admin.
- **PHP:** the admin installs versions from the panel after the first login (8.3 and 8.4 suggested); new vhosts default to 8.3.
- **Admin IP allowlist:** off by default, configurable in server settings; when set, admin logins from other addresses are refused by the web process.
- **Backups (phase 2):** local, under `/var/backups/paddock/`, 7 daily copies per vhost; off-host targets come later.
- **Panel hostname:** given to `bootstrap.sh --hostname`; for the test VM use any name that resolves to it.
- **Repository owner:** `<owner>` stays a placeholder until set.

## 16. AlmaLinux 10 readiness (not in scope before phase 3)

Paddock targets EL 9 first but must not block a later move to EL 10. Rules that keep that path open:

- **Platform layer:** all OS-specific choices (package names, module commands, repository URLs, Remi release package) live in `internal/platform`, keyed on the major version from `/etc/os-release`. No other package hard-codes `el9`.
- **MariaDB:** EL 10 drops dnf modules and ships MariaDB 10.11 as the default `mariadb-server` package, the same version Paddock uses on EL 9, so database files carry over unchanged.
- **PHP:** Remi publishes the same `phpNN` collections for EL 10 under the same `/opt/remi/phpNN` paths, so units and configs stay identical.
- **CPU:** AlmaLinux 10 defaults to x86-64-v3 and offers an x86_64_v2 variant for older CPUs; `bootstrap.sh` and the upgrade check report which one applies.
- **Packages:** the same static binary goes into an el9 and an el10 RPM; the repository path uses `$releasever`.

### 16.1 Upgrade paths

**Preferred: new server and migration.** Install a fresh AlmaLinux 10 server with Paddock, then move vhosts with `paddock export` and `paddock import` (files, databases, users, certificates, settings) followed by a final delta sync during a short freeze. Each vhost moves on its own with a rollback path, and the old server stays intact until the last vhost is gone. If the public IP cannot move with it, owners must update DNS.

**In place: ELevate.** AlmaLinux's ELevate tool (Leapp) upgrades 9 to 10 in place. Remi is not among ELevate's supported third-party repositories, so Paddock wraps the run:

1. `paddock os-upgrade prepare`: check CPU level and free space, back up `/var/lib/paddock`, and all databases, record each vhost's PHP version, stop all vhost units, remove Remi packages and `remi-release-9`, disable the Paddock repository.
2. `leapp preupgrade`, resolve inhibitors, `leapp upgrade`, reboot (all sites down for the duration).
3. `paddock os-upgrade finish`: install `remi-release-10` and the recorded PHP versions, re-enable the Paddock repository (now `el10`), `dnf upgrade paddock`, rerun `bootstrap.sh`, `paddock reconcile --all`, start vhosts, run the red-team checks.

The in-place path is only offered once phase 0 checks pass on EL 10 and the procedure has been rehearsed on a snapshot of a real server.

# Part 2: Tasks

Phase gates: phase 1 starts only when every phase 0 check passes; phase 2 starts only when a fresh install serves a PHP application through the panel; phase 3 starts after an external security review of agent and panel.

## Phase 0: proof of concept on a VM

Throwaway shell scripts in `poc/`, run as root on a disposable AlmaLinux 9.4+ VM. Each script prints `PASS` or `FAIL` with the reason and cleans up after itself. Record results and any design corrections in `docs/poc-results.md`, and update part 1 where a check changes the design.

- [ ] **T0.1 VM baseline.** `poc/Vagrantfile` (box `almalinux/9`, second disk) or `poc/cloud-init.yaml` for a reproducible test VM; `poc/00-setup.sh` installs EPEL, Remi, httpd, mod_md, mariadb 10.11, php83 and php84 FPM, fail2ban, creates an XFS loop device mounted at `/srv/www` with `prjquota`.
    - Acceptance: script is idempotent; `xfs_quota -x -c state /srv/www` shows project quota on.
- [ ] **T0.2 Sandbox visibility.** Two test vhost users with units using the drop-in from §7.1.
    - Acceptance: inside A's unit, `/srv/www` lists only A; B's FPM socket path does not exist; `/dev/shm` is private; `ps` shows only A's processes.
- [ ] **T0.3 Backend Apache as vhost user.** Unit and config from §7.1 and §7.2.
    - Acceptance: process runs as `v00001` in `httpd_t` (`ps -eZ`), binds `127.64.0.1:81`, serves a static file and a PHP file; module file names in §7.2 verified.
- [ ] **T0.4 Remi FPM label and switch.** FPM unit for 8.3, then switch to 8.4 per §8.
    - Acceptance: FPM runs in `httpd_t`, or a documented `semanage fcontext` equivalence fixes it; switch completes with no failed requests in a 1 req/s loop.
- [ ] **T0.5 MariaDB from the sandbox.** Primary DB user per §9.
    - Acceptance: PHP in A's unit connects passwordless via `unix_socket`; A cannot connect as B's user; escaped grant gives access to `v00001_app` and not `v00001xapp`.
- [ ] **T0.6 Loopback rule.** nftables file from §7.6.
    - Acceptance: A's PHP cannot connect to B's backend; the front `apache` user can; rule survives `firewall-cmd --reload`.
- [ ] **T0.7 SFTP jail.** Mount unit and sshd drop-in from §7.5.
    - Acceptance: SFTP login sees only `/site`; TCP forwarding to `127.0.0.1:3306` works; forwarding to any other target fails.
- [ ] **T0.8 Shell jail.** Jail per §7.5 with private procfs.
    - Acceptance: shell sees only its own processes and user; `php -v` works; masked `user@<uid>.service` does not break login; session lands in `user-<uid>.slice`; `sudo` and `su` inside the jail cannot gain privileges.
- [ ] **T0.9 Kernel settings.** sysctl file from §7.6.
    - Acceptance: with `user.max_user_namespaces = 0`, all units from T0.2 to T0.8 still start.
- [ ] **T0.10 PHP application.** A plain PHP application in vhost A behind the front proxy.
    - Acceptance: PHP writes and updates files in its own tree, owned by the vhost user; `open_basedir` stops writes outside it; sessions persist; PHP sees HTTPS behind the front proxy.
- [ ] **T0.11 Scale.** 500 idle vhosts.
    - Acceptance: record memory per idle vhost, boot time to all units active, and `systemctl daemon-reload` time in `docs/poc-results.md`.
- [ ] **T0.12 Red team.** Script `poc/90-redteam.sh` runs every attempt from §7.7 as vhost A against vhost B.
    - Acceptance: every attempt fails.

## Phase 1: core

- [x] **T1.1 Repository skeleton.** `go.mod` with only the allowed modules, `cmd/paddock` with subcommands `agent`, `web`, `setup`, `teardown`, `reconcile`, `admin`, `agent-notify` (stubs), `scripts/check.sh` running gofmt, vet, and tests, `README.md` (purpose, status, test-VM instructions), `.gitignore`. Ask the owner which license to add.
    - Acceptance: `go build ./cmd/paddock` succeeds; `scripts/check.sh` passes.
    - Done: the repository already carried the MPL-2.0 license. `scripts/check.sh` also runs golangci-lint and shellcheck when installed; `.github/workflows/ci.yaml` runs the same checks.
- [x] **T1.1a Platform layer.** `internal/platform` per §16: detect the EL major version and return package names, module commands, Remi release URL, and repository paths; EL 9 implemented, EL 10 stubbed with a clear error.
    - Acceptance: no package outside `internal/platform` contains `el9`, `el10`, or `dnf module` strings (enforced by a test).
- [x] **T1.2 Validators.** `internal/validate`: vhost ID, owner ID, domain names (IDNA to ASCII, no wildcards), DB and DB-user suffixes, PHP versions, SSH public keys (`ssh-ed25519`, `ecdsa-sha2-*`, `ssh-rsa` with at least 3072 bits), path containment helper that rejects symlinks.
    - Acceptance: table-driven tests including hostile inputs (`../`, NUL bytes, newline injection, uppercase, overlong names, shell metacharacters).
    - Done: `Domain` converts names with `golang.org/x/net/idna` (UTS #46 lookup profile, non-transitional), approved as an allowed module.
- [x] **T1.3 System runner.** `internal/system.Runner` interface with `Run(ctx, argv []string, opts)`; real implementation via `os/exec` with a clean environment; fake implementation that records calls and returns scripted results.
    - Acceptance: no package outside `internal/system` imports `os/exec` (enforced by a test that scans imports).
- [x] **T1.4 State store.** `internal/state` with embedded migrations for the tables in §13 and typed accessors.
    - Acceptance: migrations apply to an empty file and are idempotent; accessor tests run against a temp database.
    - Deferred: the schema covers every §13 table; accessors for `databases`, `db_users`, `access_accounts`, `ssh_keys`, and `certs` arrive with T1.12 to T1.14, which define how they are used. `go.mod` lists the indirect modules that `modernc.org/sqlite` and `golang.org/x/crypto` pull in; the direct requirements are only the allowed ones.
- [x] **T1.5 Renderer.** `internal/render` with templates for every file in §7; a `Root` field prefixes all output paths; atomic write helper (temp file, fsync, rename) and restore of the previous version.
    - Acceptance: golden-file tests match the reference outputs in §7 for vhost `v00012`; rendering rejects unvalidated input types.
    - Done: a test also compares the reference renders with the §7 code blocks in this file, so a spec change fails the build until templates follow. Choices the spec leaves open, to confirm: uploaded certificates live at `/etc/pki/paddock/<vhost id>.crt` and `.key`, and their port 80 vhost redirects to HTTPS because `MDRequireHttps` applies only to managed domains; a suspended vhost answers `Redirect 503 /` on port 443; the global front config adds `MDCertificateAgreement accepted` (mod_md needs it for Let's Encrypt) and a `Require local` `md-status` location for §10.
    - Deferred: disabling `mod_status` needs a change in `conf.modules.d`, so it belongs to `bootstrap.sh` (T1.26). The PoC corrections to §7.2 (`DefaultRuntimeDir`, `combined` log format) wait for phase 0 results.
- [x] **T1.6 Agent server.** Socket at `/run/paddock/agent.sock`, `SO_PEERCRED` check (UID 0 or `paddock`), newline JSON protocol from §4, op registry with class (owner, admin, system), audit log entries without secrets, job runner for long operations.
    - Acceptance: tests over a socketpair cover unknown op, malformed JSON, oversized request (limit 1 MiB), forbidden caller UID, audit content.
    - Done: besides the four classes of §4, a `root` class serves root CLI commands such as `paddock admin add` (T1.7). Audit arguments are redacted by name (`password`, `secret`, `token`, `totp`, `code`, `pem`, and per-operation extras); errors that are not protocol errors reach the caller as `internal` without detail. Admin operations are denied until T1.7 supplies the gate.
    - Deferred: wiring `paddock agent` to `Listen` and `Serve` comes with T1.7, the first task with a CLI client.
- [x] **T1.7 Admin identity and TOTP gate.** `admins` table, `admin.totp.verify`, admin ops require a valid unused code or an open 10-minute window for that admin; root CLI `paddock admin add` and `paddock admin totp-reset` talk to the agent over the socket as UID 0.
    - Acceptance: replayed code rejected; expired window rejected; a user marked admin only in `web.db` cannot run admin ops; owner-class callers never can.
    - Done: root operations are `admin.add` and `admin.totp.reset`; they return the `otpauth://` URI once and the CLI prints it. A code is single-use per time step: after a code is accepted, codes from that step or earlier fail. `paddock agent` now listens and serves these operations.
    - Deferred: `paddock admin add` takes the admin's panel user ID; creating the matching `web.db` user belongs to the web tasks (T1.18, T1.24).
- [x] **T1.8 Owners and limits.** `owner.*` ops; limits and defaults from §5; limit checks shared by all ops that consume quota.
    - Acceptance: creating a vhost, database, or access account beyond the limit returns `limit_exceeded`.
    - Done: quota checks run inside the state transaction that adds the vhost, database, DB user, or access account, so concurrent requests cannot both pass; shell accounts also need `shell_allowed`. Tests cover each resource from the store through the socket. `owner.create` and `owner.limits.set` merge given fields onto the defaults or current limits.
    - Deferred: the `vhost.create`, `db.create`, and `access.create` operations arrive with T1.10, T1.13, and T1.14 and use these store methods. Applying changed limits to owner slices and FPM pools on the host comes with T1.10 and T1.16.
- [ ] **T1.9 PHP versions.** `php.version.install` and `php.version.remove` via dnf (Remi packages), render the FPM unit template per version, refuse removal while vhosts use the version.
    - Acceptance: fake-runner tests for both paths; integration test installs 8.4 on the VM.
    - Status: fake-runner tests pass for install, remove, refusal while in use, and rollback after a failure at each step. `test/integration/php_test.go` installs and removes 8.4 through an in-process agent; it has not run on a VM yet, so the task stays open.
- [ ] **T1.10 Vhost create and delete.** Full lifecycle from §8 with step-by-step rollback.
    - Acceptance: fake-runner tests inject a failure at each step and assert complete rollback; integration test creates a vhost, serves `phpinfo()` through the front, deletes it, and leaves no user, unit, mount, or config behind.
    - Status: fake-runner tests fail each of the 15 create commands in turn, and the FPM socket wait, and check that files, directories, state, and every completed step are undone. Delete tests cover scoping, confirmation, a unit that will not stop, and a rerun after a partial failure. `test/integration/vhost_test.go` covers the VM half; it has not run yet, so the task stays open.
    - Choices to confirm: the group is created with `groupadd -g <uid>` before `useradd -g`, so the GID always equals the UID, and vhost users get no subordinate ID ranges (`-K SUB_UID_COUNT=0`). Each vhost's XFS hard limit is the owner's `disk_mb` until T1.15 enforces the owner total. A per-vhost `tmpfiles.d` entry recreates `/run/paddock/fpm/<id>` at boot. `vhost.delete` requires `confirm` to repeat the primary domain. Delete prunes archives older than 7 days and leaves the owner slice, which other vhosts share. Delete refuses to remove a tree with anything mounted below it.
    - Deferred: the primary DB user (create) and dropping databases and DB users (delete) arrive with `internal/mariadb` in T1.13.
    - Added: `vhost.create` takes an optional `database` suffix; when given, the job also creates that empty database for the vhost, counted against the owner's limit and rolled back with the vhost. The new-vhost form offers it. No tables are created; databases start empty.
- [ ] **T1.11 PHP switch, suspend, resume.** §8.
    - Acceptance: integration test switches 8.3 to 8.4 under a request loop with no errors; suspended vhost returns 503.
    - Status: `vhost.php.switch`, `vhost.suspend`, and `vhost.resume` run as jobs with fake-runner tests for each sequence and rollback. `test/integration/vhost_test.go` covers the acceptance on the VM; it has not run yet, so the task stays open.
    - Choices to confirm: only an active vhost can switch PHP; a suspended one must be resumed first. If the FPM socket is missing after the old master stops (PoC question 5), the switch restarts the new unit, which costs a brief gap instead of an outage. Suspend points the front at `Redirect 503 /` before stopping the units, and resume starts the units before restoring the proxy.
    - Deferred: updating the shell jail's `php` link comes with shell jails in T1.14. Front TLS mode is always `mod_md` until T1.12 records uploaded certificates.
- [x] **T1.12 Front Apache and certificates.** Front vhost rendering, `MDNotifyCmd` handler (`paddock agent-notify md-renewed` asks the agent to validate and reload), `md-status` reader, custom certificate upload with key and chain validation.
    - Acceptance: `apachectl configtest` failure restores the previous file and reports `apply_failed`; uploaded certificate whose key does not match is rejected.
    - Done: `cert.upload` validates the chain and key (key matches the leaf, valid now, covers every domain, RSA of 2048 bits or more or ECDSA P-256/P-384), stores them re-encoded under `/etc/pki/paddock/` (key `0600`), and switches the front to them; `cert.status` merges the stored record with `md-status`; `paddock agent-notify md-renewed` calls the root-only `front.md-renewed`, which runs `configtest` and a graceful reload. Uploaded certificates survive suspend and resume.
    - To verify on the VM (added to `docs/poc-results.md`): the user `MDNotifyCmd` runs as, the `md-status` JSON layout, and whether tenant PHP can read `md-status` on loopback.
    - Deferred: returning from an uploaded certificate to ACME has no operation yet.
- [ ] **T1.13 MariaDB.** `internal/mariadb`: identifier quoting, grant escaping with the 64-character check, `db.*` and `dbuser.*` ops, usage query, quota enforcement per §9.
    - Acceptance: unit tests for escaping; integration test proves cross-vhost access is denied and quota revocation works.
    - Status: `internal/mariadb` quotes identifiers and string literals, escapes `_` in grants with the 64-character check, and runs SQL through the `mariadb` client on stdin (no driver is an allowed module), so passwords never reach argv. Operations: `db.create`, `db.delete`, `dbuser.create`, `dbuser.delete`, `dbuser.password.reset`; `vhost.create` now creates the primary DB user and `vhost.delete` drops the vhost's databases and DB users. `test/integration/vhost_test.go` checks cross-vhost access on the VM; quota revocation comes with T1.15. Neither has run yet, so the task stays open.
    - Choices to confirm: databases are created in `utf8mb4` with `utf8mb4_unicode_ci`, since MariaDB 10.11 defaults to `latin1`. Extra DB users get `all` (ALL PRIVILEGES) or `read` (SELECT, SHOW VIEW) on every database of their vhost through the pattern `v00012\_%`, which also covers databases created later. Generated passwords are 24 letters and digits, returned once; the primary user's initial password is discarded and `dbuser.password.reset` with an empty suffix sets a new one. Revokes run one statement at a time and treat "no such grant" (1141, 1147) as done, because a plain `REVOKE` fails on a missing grant; `REVOKE IF EXISTS` is not relied on.
- [ ] **T1.14 Access accounts.** `access.*` and key ops (passwords passed to `chpasswd` on stdin, never in argv): groups, jails, mount units, shell jail contents, `authorized_keys` files, `user@<uid>.service` masking, user slice drop-in.
    - Acceptance: integration tests repeat T0.7 and T0.8 through the agent.
    - Status: `access.create`, `access.delete`, `access.key.add`, and `access.key.remove` with fake-runner tests, including rollback of a half-built shell jail; passwords reach `chpasswd` on stdin only. `test/integration/access_test.go` repeats T0.7 and T0.8 on the VM; it has not run yet, so the task stays open.
    - Choices to confirm: each vhost has at most one access account, named after the vhost and logging in as the vhost user, which is what `ChrootDirectory /srv/jail/%u` allows (PoC question 7); `max_access_accounts` counts these across the owner's vhosts. Shell jails follow the PoC layout: a `php` link in `/opt/paddock/bin` with `PATH` set in the jail's `/etc/profile`. Deleting an account ends only its `sshd` processes, since FPM and Apache share the vhost UID. Passwords are 12 to 128 printable ASCII characters without `:`.
- [ ] **T1.15 Usage and events.** XFS project usage, database sizes, quota notifications at 90 % and enforcement at 100 %; `events.list` feed.
    - Acceptance: filling a vhost to its limit produces the expected events and enforcement.
    - Status: `ScanUsage` (every 10 minutes in the agent, and on demand) sums each owner's XFS project usage and database sizes against `disk_mb`. At 90 % it records `quota_warning`; at 100 % it freezes each vhost's XFS hard limit at its current size, revokes INSERT, UPDATE, and CREATE from the primary user and full-privilege DB users, and records `quota_exceeded`; back under the limit it restores both and records `quota_cleared`. It also records `cert_expiring` once a day for certificates within 14 days of expiry. Failed applies, renewed certificates, and added SSH keys are events too; `events.list` pages through them and `usage.get` reports an owner's use. A fake-runner test walks one owner from 60 % to over the limit and back. `test/integration/vhost_test.go` (`TestQuotaRevocation`) checks the same on the VM, which also confirms the `xfs_quota report -p -N -n -b` output format; it has not run yet, so the task stays open.
    - Deferred: a database or vhost created while its owner is over the limit starts unrestricted until the next scan.
- [ ] **T1.16 Reconcile.** `reconcile.all` and `paddock reconcile --all` re-render and re-apply everything from `state.db`.
    - Acceptance: deleting a vhost's rendered configs by hand and reconciling restores a working vhost.
    - Status: `Reconcile` rewrites PHP unit templates and, for every active or suspended vhost, its directories, configs, front vhost (by status and certificate source), authorized keys, and shell jail; reloads systemd when anything changed; brings units to the state the vhost's status calls for, restarting those whose config changed; and reloads the front after `apachectl configtest`, restoring the front files if the check fails. A vhost it cannot repair is reported without stopping the rest. Admins call `reconcile.all` (a job); root calls `paddock reconcile -all`, served synchronously by the root operation `reconcile.run`. Fake-runner tests cover repair, an idle rerun, suspended and shell vhosts, and a failing check; `TestReconcileRestoresVhost` covers the VM half and has not run yet, so the task stays open.
    - Deferred: reconcile does not recreate Linux users, MariaDB users, or databases; it reports the vhost instead. Vhosts in status `creating`, `deleting`, or `failed` are reported for an admin to resolve.
- [x] **T1.17 Web server base.** TLS on `:8443` with the self-signed certificate, `:8080` redirect, security headers from §11.3, router where every route declares a permission (startup fails otherwise), agent client, embedded templates and static files.
    - Acceptance: test asserts startup failure for a route without permission; header tests.
    - Done: routes declare one of the §11.1 permissions; `Build` refuses unknown or missing ones, handlers, or duplicates. Templates and static files (htmx 2.0.11, vendored with its 0BSD licence and verified npm integrity) are embedded. The web process refuses to run as root and reaches the host only through `DialAgent`, one connection per call. HSTS turns on once T1.20's certificate is trusted.
- [x] **T1.18 Local authentication.** Argon2id with parameters from §11.2, common-password list, owner TOTP enrollment and verification, admin second factor through `admin.totp.verify`, recovery codes, login flow with dummy hashing, rate limiting with backoff, login events.
    - Acceptance: tests for timing-safe comparisons, backoff, TOTP replay, recovery code single use.
    - Done: `internal/auth` hashes with Argon2id in PHC format and rehashes on parameter change; the common-password list is SecLists' 10k list (MIT, `internal/auth/data/`). Owners' second factor is TOTP or a recovery code; admins' goes to the agent's `admin.totp.verify`, which also opens their admin window. A login from a new IP notifies the user. `web.db` is `internal/web/store` with its own migrations.
- [x] **T1.19 Sessions, CSRF, step-up.** §11.3.
    - Acceptance: tests for cookie attributes, idle and absolute expiry per role, token rotation, Origin check, CSRF token check, step-up enforcement on each listed action.
    - Done: tokens rotate on login, after the second factor, and when impersonation starts or stops; a password change ends the user's other sessions. Step-up covers password and second-factor changes, SSH keys, access accounts, and deletions; email and API tokens get it when they exist (T2.7, T2.8). An owner whose admin requires TOTP can only reach the security page until enrolled.
- [ ] **T1.20 Panel certificate.** `internal/acme` HTTP-01 client over `/run/paddock/acme/acme.sock`, renewal 30 days before expiry, `GetCertificate` fallback to self-signed, HSTS once trusted.
    - Acceptance: test against Let's Encrypt staging on the VM with a real hostname.
    - Status: `internal/acme` wraps `x/crypto/acme/autocert` (HTTP-01 only, panel hostname only, renewal 30 days ahead) and serves challenges on `/run/paddock/acme/acme.sock`. No handshake waits for the CA: the self-signed certificate is served while one background fetch runs. `paddock web -acme-directory` takes the staging URL for the acceptance test, which needs the VM.
    - Choice to confirm: the challenge socket is mode `0666` so Apache can connect; it only answers public challenge tokens.
- [x] **T1.21 Owner UI.** Pages from §11.4 for owners: dashboard, vhosts, PHP switch, databases, DB users, access accounts and keys, certificates, profile, security. Owner-scoped queries everywhere.
    - Acceptance: handler tests prove another owner's IDs return 404; templates use `.Can` for every action.
    - Done: tests run the panel against the agent's real operations with a fake host. A test maps every posting form to its route and fails unless the template checks that route's permission. New agent reads `vhost.list`, `vhost.get`, `php.version.list`, `owner.get` and `vhost.update` serve the pages.
    - Deferred: vhost logs need an agent operation that reads them; the vhost page has no log view yet. PHP settings in `vhost.update` are not implemented.
- [x] **T1.22 Admin UI.** Owners, limits, PHP versions, server status, audit log, impersonation with dual-identity audit and owner notification; admin actions prompt for TOTP and pass it to the agent.
    - Acceptance: impersonated actions record both identities; admin action without TOTP fails at the agent, not only in the UI.
    - Done: admin forms carry an optional TOTP field sent with the request's first admin call; an expired window shows an unlock form. Creating an owner also creates its first panel user with a one-time password.
- [ ] **T1.23 Notifications.** Poll `events.list`, store notifications, stream over SSE, mark as read.
    - Acceptance: an apply failure appears in the owner's browser without reload.
    - Status: `PollEvents` turns agent events into notifications (owner's users, plus admins for apply failures and owner-less events), stores the cursor in `web.db`, and pushes them over Server-Sent Events; a test sees an apply failure arrive on an open stream. `static/app.js` updates the page from the stream; checking that in a real browser is still open.
- [x] **T1.24 CLI.** `paddock setup` per §14.4; `paddock admin reset-password <user>`; `paddock reconcile --all`.
    - Acceptance: `setup` is idempotent and prints secrets only on first run; reset ends the user's sessions.
    - Done: `paddock setup [--admin NAME]` creates `state.db` and `web.db` and the first admin, and hands `web.db` to user `paddock`; a rerun prints no secrets. `paddock admin add NAME` creates the `web.db` user too (removing it if the agent refuses), `paddock admin totp-reset NAME` looks the admin up by name, and `paddock admin reset-password NAME` ends the user's sessions; each hands `web.db` back to user `paddock`.
    - Changed: host preparation (ports, `/srv/www`, host configs, MariaDB, firewall, services) moved from `paddock setup` to `bootstrap.sh` (T1.26), the panel certificate to `paddock web`, and PHP installation to the admin panel. The host configs live in `deploy/etc/` and ship under `/usr/share/paddock/etc/`.
- [ ] **T1.25 RPM and GitHub release pipeline.** `packaging/paddock.spec` per §14.2, sysusers and tmpfiles files, systemd units in `deploy/`, `.github/workflows/release.yaml` per §14.1 (build in `almalinux:9`, publish the Release with `SHA256SUMS`, deploy the dnf repository to Pages), `scripts/build-rpm.sh` for local builds on the build VM.
    - Acceptance: `rpmlint` reports no errors; pushing a test tag produces a Release and an updated Pages repository; on a fresh VM, `dnf install paddock` from the Pages URL succeeds; `dnf remove` leaves vhosts and data intact.
    - Status: the spec installs the binary, units, sysusers and tmpfiles files, `deploy/etc/` under `/usr/share/paddock/etc/`, and the state directories with their §6 modes. `release.yaml` builds both architectures in `almalinux:9`, runs `rpmlint`, publishes the Release with the RPMs, `bootstrap.sh`, and `SHA256SUMS`, then calls `pages.yaml`, which rebuilds the Pages site: a landing page from `pages/index.html` with the latest release filled in, and the repository at `el9/<arch>/` from the last five releases (empty metadata before the first release). `pages.yaml` also runs when the landing page changes on `main`, or on demand. CI builds the x86_64 RPM and runs `rpmlint` on every PR. `paddock-httpd@.service` in `deploy/` is tested against the renderer. Release `v0.0.1` (2026-11-18) ran the pipeline end to end: RPMs built and linted, the Release published, and the dnf repository deployed to Pages. Open: install and removal on a VM.
    - Choices to confirm: `paddock-nft` also gets `%systemd_post` and `%systemd_preun` but is not restarted on upgrade; `rpmlint` filters for deliberate findings (private state directories, the static binary, no signature until T2.9) live in `packaging/paddock.rpmlintrc`; `/run/paddock` is `0755 root:root`; the web user creates its challenge socket in `/run/paddock/acme` (`paddock:paddock`, labelled `httpd_var_run_t` by the `paddock` SELinux module), so it cannot replace `agent.sock`.
- [ ] **T1.26 Bootstrap.** `packaging/bootstrap.sh` per §14.3 with the pinned Remi key fingerprint.
    - Acceptance: on a fresh VM, bootstrap completes, prints credentials, and the panel creates a vhost serving a PHP application; rerunning bootstrap changes nothing; a tampered Remi key fingerprint aborts the run.
    - Status: `packaging/bootstrap.sh` runs §14.3 steps 1 to 12 and ends with `paddock setup`, which prints the first admin's credentials. It writes a config only when its content differs, so a rerun changes nothing and restarts only services whose config changed. The release workflow fills in the repository owner; a copy without one needs `--rpm`. Remi trust: the script imports only keys inside `remi-release-9` whose primary fingerprint is pinned, then requires `rpm --checksig` to pass. `packaging/bootstrap_test.sh` sources the script and tests the validators, the port parser, the config writer (content, idempotence, keep marker), the subordinate ID overlap check and the `login.defs` reader, and the fingerprint check against a generated key; it runs in `scripts/check.sh` and CI.
    - Pinned Remi key: `B1ABF71E14C9D74897E198A8B19527F1478F8947`, the key ID `b19527f1478f8947` that `remi-release-9.rpm` downloaded from rpms.remirepo.net was signed with on 2026-11-17. The VM run is still to do.
- [ ] **T1.27 Integration suite and red team.** Collect integration tests; port `poc/90-redteam.sh` to run against panel-created vhosts.
    - Acceptance: full suite passes on a fresh VM; red team finds no cross-tenant access.
    - Status: `test/integration/` runs every test through one in-process agent on the host's own `state.db`, so test vhosts take the next free numbers and never collide with vhosts the panel created; the installed `paddock-agent` and `paddock-web` are stopped for the run and started again afterwards. Each test creates its owners and vhosts through agent operations, as the panel does, and deletes them when it ends. `TestRedTeam` ports `poc/90-redteam.sh`: every §7.7 row, tried from A's PHP (sandbox, SELinux, UID) and, where the PoC did, as A's UID in the host namespaces, the front Apache user, or A's shell account. `TestVhostCreateWithDatabase` covers the optional empty database. `make integration` runs the suite (`RUN=` selects tests). Open: the run on a fresh VM after `bootstrap.sh`.
    - Choices to confirm: the suite enrols an admin `itest` with user ID 2^40 in `state.db` and keeps it between runs (a rerun resets its TOTP secret); with no `web.db` user it cannot log in to the panel.

## Phase 2: comfort

- [ ] **T2.1 phpMyAdmin sign-on.** §12, including temporary DB users and expiry cleanup.
- [ ] **T2.3 Backups and restore.** Files plus per-database dumps per vhost, retention, restore to the same or a new vhost.
- [ ] **T2.4 OIDC login.** §11.2, generic provider configuration, profile linking.
- [ ] **T2.5 GitHub login.** §11.2.
- [ ] **T2.6 Invitations.** Single-use, 72 h, link identities on first login.
- [ ] **T2.7 API tokens.** Scoped, hashed, expiring; step-up on creation.
- [ ] **T2.8 Outbound notifications.** SMTP relay and webhook forwarding, password reset by email.
- [ ] **T2.8a Export and import.** `paddock export <vhost>` and `paddock import` with a final delta sync, per §16.1; also the basis for moving vhosts between servers.
    - Acceptance: a vhost with a database moves between two VMs with no data loss and under one minute of read-only time.
- [ ] **T2.9 Package signing.** Signing key held outside GitHub or in a protected `release` environment with required reviewers; `rpmsign --addsign` for RPMs, detached signature for `repodata/repomd.xml` and `SHA256SUMS`; public key `RPM-GPG-KEY-paddock` on Pages with its fingerprint in `README.md` and pinned in `bootstrap.sh`; repo file switched to `gpgcheck=1`, `repo_gpgcheck=1`. Existing servers switch when `bootstrap.sh` is rerun.
    - Acceptance: a tampered RPM or repository metadata fails `dnf install` on a test VM.
- [ ] **T2.10 Security review.** External review of agent and panel; fix findings before phase 3.

## Phase 3: extensions

- [ ] **T3.1 Passkeys.** WebAuthn registration and login.
- [ ] **T3.2 Collaborators.** Invited users restricted to selected vhosts.
- [ ] **T3.3 Egress rules.** Per-vhost nftables `meta skuid` allowlists and mail port blocks.
- [ ] **T3.4 SELinux module for Paddock.** Confine agent and web instead of `unconfined_service_t`.
    - Starting point: `deploy/selinux/paddock.cil` already lets `httpd_t` connect to any `unconfined_service_t` Unix socket, for the ACME challenge socket. Narrow that rule to the web domain.
- [ ] **T3.5 AlmaLinux 10.** EL 10 platform implementation, el10 RPMs, phase 0 checks repeated on EL 10, `paddock os-upgrade prepare` and `finish` per §16.1, rehearsal on a snapshot.
    - Acceptance: a fresh EL 10 install passes the integration suite; an EL 9 test server with three vhosts on different PHP versions upgrades in place and passes the red-team checks afterwards.
