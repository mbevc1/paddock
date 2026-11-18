# paddock

Paddock is a simple web hosting panel for AlmaLinux 9.4+. It runs WordPress and custom PHP sites in isolated vhosts: each vhost has its own Linux user, its own sandboxed Apache and PHP-FPM, and cannot see or touch another vhost's files or processes. Owners manage several vhosts within limits an admin sets.

## Status

Early development; nothing here is ready to install. `docs/plan.md` holds the specification (part 1) and the task list (part 2).

- **Phase 0:** proof-of-concept scripts in `poc/` check the design on a VM. Results go into `docs/poc-results.md`.
- **Phase 1:** the `paddock` binary. Subcommands exist as stubs.

## Development

Requires Go 1.27.

```bash
go build ./cmd/paddock
scripts/check.sh
```

`scripts/check.sh` runs gofmt, `go vet`, golangci-lint and shellcheck when installed, and the unit tests. Unit tests run anywhere as a normal user. Never run the agent, `paddock setup`, or the bootstrap script on a development machine: they change the host as root.

## Test VM

Host-changing code runs only on a disposable AlmaLinux 9.4+ VM with a second disk for `/srv/www`. `poc/Vagrantfile` defines one (box `almalinux/9`):

```bash
cd poc
vagrant up
vagrant ssh -c 'sudo /vagrant/poc/00-setup.sh --device /dev/vdb --format'
vagrant snapshot save clean
```

See `poc/README.md` for the phase 0 checks.

## License

[Mozilla Public License 2.0](LICENSE).
