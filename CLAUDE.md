# Paddock

Paddock is a hosting panel for AlmaLinux 9.4+ that runs WordPress and custom PHP sites in vhosts that cannot see or touch each other's files or processes. Owners manage several vhosts within limits set by an admin.

Read `docs/plan.md`: part 1 is the full specification, part 2 the task list. Work through the tasks in order unless told otherwise. Where the plan leaves a choice open, use the defaults in §15; ignore §16 (AlmaLinux 10) until phase 3.

## Architecture in one paragraph

One Go binary, `paddock`, runs as two processes. `paddock agent` runs as root, listens only on `/run/paddock/agent.sock` (`root:paddock`, `0660`), verifies callers with `SO_PEERCRED`, and executes a fixed set of typed operations that change the host. `paddock web` runs as user `paddock`, serves the panel over TLS on `:8443` (`:8080` redirects), and calls the agent for every host change. Each vhost gets its own Linux user, its own sandboxed backend Apache and PHP-FPM master (systemd units), and a front Apache that only terminates TLS and proxies.

## Repository layout

```
cmd/paddock/            main: subcommands agent, web, setup, teardown, reconcile, admin, agent-notify, export, import, os-upgrade
internal/api/           request/response types shared by agent and web
internal/agent/         socket server, caller checks, op dispatch, audit
internal/agent/ops/     one file per operation group (vhost, php, db, access, cert, owner)
internal/platform/      OS-specific choices keyed on the EL major version (§16)
internal/validate/      name, path, domain, and version validators
internal/state/         state.db access and migrations (agent only)
internal/render/        config rendering; templates embedded from render/templates/
internal/system/        Runner interface for host commands, real and fake implementations
internal/mariadb/       MariaDB admin over unix_socket
internal/web/           HTTP server, routes, handlers, sessions, CSRF, SSE
internal/web/templates/ html/template pages
internal/web/static/    CSS, vendored htmx
internal/auth/          argon2id, TOTP, OIDC, GitHub OAuth2
internal/acme/          ACME HTTP-01 client for the panel certificate
deploy/                 systemd units, sysusers, tmpfiles, default configs (sshd, sysctl, nftables, fail2ban, Apache)
packaging/              paddock.spec, bootstrap.sh
.github/workflows/      release.yml: build, GitHub Release, dnf repository on Pages (unsigned until T2.9)
poc/                    phase 0 scripts and test-VM definition, run on a test VM only
test/integration/       tests that need a real AlmaLinux VM
```

## Allowed dependencies

Standard library first. Only these modules may appear in `go.mod`:

- `golang.org/x/crypto` (argon2, acme, ssh key parsing)
- `golang.org/x/net` (idna: internationalized domain names)
- `golang.org/x/sys` (unix: peer credentials, mounts, xattrs)
- `modernc.org/sqlite` (pure Go SQLite)

htmx is vendored as one file in `internal/web/static/`. Ask before adding anything else.

## Security invariants

Never break these. If a task seems to require breaking one, stop and ask.

1. **No shell strings.** Run host commands only through `internal/system.Runner` with an argv slice. Never `sh -c`, never string concatenation into a command. Secrets go to commands on stdin, never in argv.
2. **Validate before use.** Every name, path, domain, and version passes `internal/validate` before it reaches a template, a command, or SQL. Vhost IDs match `^v[0-9]{5}$`.
3. **Paths stay inside their root.** Resolve paths and reject anything outside `/srv/www/<vhost>/` or `/srv/jail/<vhost>/`. Reject symlinks in paths the agent writes to.
4. **The web process never touches the host.** It holds no root privileges, writes no host config, and reaches the system only through the agent socket.
5. **The agent enforces limits and caller rights.** It checks owner limits against `state.db` on every operation and rejects admin operations without a fresh, agent-verified admin TOTP code, whatever the web process claims. Admin identities and admin TOTP secrets exist only in `state.db`, created by root CLI commands.
6. **Atomic changes with rollback.** Write configs to a temp file in the same directory, validate (`apachectl configtest`, `php-fpm -t`, `systemd-analyze verify`), rename, reload. On failure restore the previous file and reload again.
7. **Escape everything.** HTML only through `html/template`, never `template.HTML` from user input. SQL only with parameters, except MariaDB identifiers, which go through the dedicated quoting and grant-escaping helpers in `internal/mariadb`.
8. **No secrets in logs or errors.** Passwords, tokens, TOTP secrets, and session IDs never appear in logs, audit entries, or error messages.
9. **Every web route declares a permission.** The router refuses to start if a route has none.

## Development rules

- **Never run the agent, `paddock setup`, or `bootstrap.sh` on the development machine.** Host-changing code runs only on a disposable AlmaLinux 9.4+ VM.
- **Unit tests use the fake Runner** and render into a temp directory via the `Root` field on the renderer, so they run anywhere as a normal user.
- **Integration tests** in `test/integration/` carry the build tag `integration` and run on the VM.
- **Before finishing a task:** `gofmt -l .` prints nothing, `go vet ./...` passes, `go test ./...` passes.
- **Comments:** only where they explain something the code cannot; keep them short.
- **Plan tracking:** tick the task's checkbox in `docs/plan.md` when its acceptance criteria pass, and note anything deferred under the task.

## Releases

- Never create tags or push releases unless explicitly asked.
- Placeholders `<owner>` in URLs stay as they are until the repository owner is set.

## Commits

- Commit as the git user configured in the repository. Never set or change the author.
- Never add `Co-Authored-By` lines, "Generated with" footers, session links, or any other attribution.
- One task per commit where practical; subject line in the imperative, under 72 characters, prefixed with the task ID (`T1.4 Add vhost directory creation`).

## Commands

```
go build ./cmd/paddock          build
go test ./...                   unit tests
go test -tags integration ./test/integration/...   on the VM only
scripts/build-rpm.sh            on the AlmaLinux build VM only
gofmt -l . && go vet ./...      checks
```
