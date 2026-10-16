<p align="center">
  <img src="https://bongbetic.com/branding/bongbetic-logo-lockup.png" width="360" alt="Bongbetic">
</p>

<h1 align="center">void-mods</h1>

<p align="center">
  <strong>System modifications for Void Linux, packaged as installable XBPS packages</strong>
</p>

---

Void Linux keeps things small: runit instead of systemd, and no hidden machinery. That is
a good base, but some conveniences that systemd distributions take for granted are
missing. void-mods adds them back one at a time. Each mod is a self-contained directory
with its own package template, tests and documentation. Install only what you need.

## Mods

| Mod | What it does |
|---|---|
| [tæma](taema/) | Dependency-aware, self-managing cgroup v2 process scopes. Stops what a program left running in the background, keeps helpers that others still use, adopts running apps into scopes, and learns from past stops. systemd-style app scopes, `BindsTo` and `StopWhenUnneeded` for runit. |

## Layout

Each mod directory contains:

- `srcpkgs/<name>/template`: a void-packages template
- `tools/build-xbps.sh`: builds a local `.xbps` without a void-packages checkout
- `Makefile`: `make test` and `make install DESTDIR=...`
- `README.md`: use case, install and usage
- `docs/`: design notes

## Principles

- Packaged, never hand-copied: every file a mod installs belongs to an XBPS package and
  goes away with `xbps-remove`.
- Off until enabled: services install disabled, as Void expects, and start in the safest
  mode.
- Small privileged surface: the parts that run as root are short, self-contained and
  validate their input on their own.
- Standard library and base-system tools only, unless a mod's README says otherwise.

## License

MIT. See [LICENSE](LICENSE).
