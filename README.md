# paddock

Paddock is a simple web hosting panel for AlmaLinux 9.4+. It runs PHP sites in isolated vhosts: each vhost has its own Linux user, its own sandboxed Apache and PHP-FPM, and cannot see or touch another vhost's files or processes. Owners manage several vhosts within limits an admin sets.

## Status

Early development; nothing here is ready to install. The project page with install instructions and the dnf repository is at https://mbevc1.github.io/paddock/. `docs/plan.md` holds the specification (part 1) and the task list (part 2).

- **Phase 0:** proof-of-concept scripts in `poc/` check the design on a VM. Results go into `docs/poc-results.md`.
- **Phase 1:** the `paddock` binary. Subcommands exist as stubs.

## Development

Requires Go 1.27.

```bash
make build
make check
```

`make help` lists the targets. `make check` runs `scripts/check.sh`, which runs gofmt, `go vet`, golangci-lint and shellcheck when installed, the unit tests, and `packaging/bootstrap_test.sh`. Unit tests run anywhere as a normal user. Never run the agent, `paddock setup`, or the bootstrap script on a development machine: they change the host as root.

## Test VM

Host-changing code runs only on a disposable AlmaLinux 9.4+ VM with a second disk for `/srv/www`. `poc/Vagrantfile` defines one (box `almalinux/9`):

```bash
cd poc
vagrant up
vagrant ssh -c 'sudo /vagrant/poc/00-setup.sh --device /dev/vdb --format'
vagrant snapshot save clean
```

See `poc/README.md` for the phase 0 checks. After `bootstrap.sh`, the integration suite and red team run as root on the VM:

```bash
sudo PADDOCK_INTEGRATION=1 make integration
```

It stops `paddock-agent` and `paddock-web` while it runs and creates and removes its own owners and vhosts. `RUN=TestRedTeam` runs one test.

## License

[Mozilla Public License 2.0](LICENSE).
