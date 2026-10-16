<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="taema/docs/assets/taema-logo-dark.svg">
    <img src="taema/docs/assets/taema-logo-light.svg" width="160" alt="tæma logo">
  </picture>
</p>

<h1 align="center">taema</h1>

<p align="center">
  <strong>Close an app. Actually close it.</strong><br>
  Dependency-aware, self-managing process scopes for Void Linux, packaged as an XBPS package
</p>

<p align="center">
  <em>Made by</em><br>
  <a href="https://bongbetic.com"><img src="https://bongbetic.com/branding/bongbetic-logo-lockup.png" width="200" alt="Bongbetic"></a>
</p>

---

Void Linux keeps things small: runit instead of systemd, and no hidden machinery. That is
a good base, but systemd-style app scopes are missing. A program you close can leave
detached children running forever. **tæma** (Icelandic for "to empty") gives every app its
own cgroup v2 scope and empties it when the app stops, while keeping any helper that
another program still uses.

This repository holds the tæma package. Everything lives in the [`taema/`](taema/)
directory, so `taema/taema` is the package inside the `taema` repository.

**Start here: [taema/README.md](taema/README.md)** for what it does, how to install it and
how to use it.

## Layout

```
taema/                  this repository
  taema/                the package
    srcpkgs/taema/      void-packages template
    tools/build-xbps.sh builds a local .xbps without a void-packages checkout
    Makefile            make test, make install DESTDIR=...
    README.md           use case, install and usage
    docs/               design notes and logo
```

## Principles

- Packaged, never hand-copied: every file installed belongs to an XBPS package and goes
  away with `xbps-remove`.
- Off until enabled: the service installs disabled, as Void expects, and starts in the
  safest mode.
- Small privileged surface: the part that runs as root is short, self-contained and
  validates its input on its own.
- Standard library and base-system tools only.

## License

MIT. See [LICENSE](LICENSE).
