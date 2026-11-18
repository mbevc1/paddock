# paddock

Paddock is a simple web hosting panel for AlmaLinux 9.4+. It runs PHP sites in isolated vhosts: each vhost has its own Linux user, its own sandboxed Apache and PHP-FPM, and cannot see or touch another vhost's files or processes. Owners manage several vhosts within limits an admin sets.

## Status

Early development. Packages are not signed yet, so install Paddock on disposable test machines only. `docs/plan.md` holds the specification (part 1) and the task list (part 2).

- **Phase 0:** proof-of-concept scripts in `poc/` check the design on a VM. Results go into `docs/poc-results.md`.
- **Phase 1:** the agent, the web panel, the RPM and the bootstrap script, released as `v0.0.1`.

## Install

On a fresh AlmaLinux 9.4+ server with SELinux enforcing and a spare disk for `/srv/www`, run the bootstrap script of a [release](https://github.com/mbevc1/paddock/releases):

```bash
VER=v0.0.1
BASE=https://github.com/mbevc1/paddock/releases/download/$VER
curl -fsSLO $BASE/bootstrap.sh
curl -fsSLO $BASE/SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
sudo bash bootstrap.sh --hostname panel.example.com --www-device /dev/vdb --format
```

It prints the first admin's credentials once; the panel is then at `https://<hostname>:8443/`. [INSTALL.md](INSTALL.md) covers requirements, options, first steps, upgrades, removal and troubleshooting. The project page is https://mbevc1.github.io/paddock/.

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
