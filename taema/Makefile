# taema: install layout for Void Linux. Paths are fixed to /usr and /etc; use DESTDIR to stage.
DESTDIR ?=
PYTHON  ?= python3
CARGO   ?= cargo
# Hermetic offline builds from rust/vendor in rust/target. Override on the
# make command line (not via the environment) to reuse a shared cache.
CARGO_TARGET_DIR = $(CURDIR)/rust/target
export CARGO_TARGET_DIR

LIBDIR    = $(DESTDIR)/usr/lib/taema/taema
BINDIR    = $(DESTDIR)/usr/bin
LIBEXEC   = $(DESTDIR)/usr/libexec/taema
SVDIR     = $(DESTDIR)/etc/sv/taema
CONFDIR   = $(DESTDIR)/etc/taema
SUDOERS   = $(DESTDIR)/etc/sudoers.d
DOCDIR    = $(DESTDIR)/usr/share/doc/taema
EXAMPLES  = $(DESTDIR)/usr/share/examples/taema
SHELLDIR  = $(DESTDIR)/usr/share/taema/shell
BASHRCD   = $(DESTDIR)/etc/bash/bashrc.d
FISHCONF  = $(DESTDIR)/usr/share/fish/vendor_conf.d
MANDIR    = $(DESTDIR)/usr/share/man/man7
MAN1DIR   = $(DESTDIR)/usr/share/man/man1
MAN5DIR   = $(DESTDIR)/usr/share/man/man5
BASHCOMP  = $(DESTDIR)/usr/share/bash-completion/completions
ZSHCOMP   = $(DESTDIR)/usr/share/zsh/site-functions
FISHCOMP  = $(DESTDIR)/usr/share/fish/vendor_completions.d
SCDOC     ?= scdoc
MAN1      = docs/taema.1 docs/taema-agent.1
MAN5      = docs/taema.toml.5 docs/taema.unit.5
MAN7      = docs/taema-learning.7

.PHONY: all test check install man vm-test vm-dry-run vm-doctor rust-helper rust-helper-release

all:
	@:

# Man pages are authored as scdoc and checked in built: `make man`
# rebuilds them when scdoc is available, otherwise keeps the
# checked-in roff so a checkout without scdoc still installs.
man: $(MAN1) $(MAN5) $(MAN7)

docs/%.1: docs/%.scd
	@if command -v $(SCDOC) >/dev/null 2>&1; then \
		$(SCDOC) < $< > $@; \
	else \
		echo "man: $(SCDOC) not found; keeping checked-in $@"; \
	fi

docs/%.5: docs/%.scd
	@if command -v $(SCDOC) >/dev/null 2>&1; then \
		$(SCDOC) < $< > $@; \
	else \
		echo "man: $(SCDOC) not found; keeping checked-in $@"; \
	fi

docs/%.7: docs/%.scd
	@if command -v $(SCDOC) >/dev/null 2>&1; then \
		$(SCDOC) < $< > $@; \
	else \
		echo "man: $(SCDOC) not found; keeping checked-in $@"; \
	fi

# The Rust helper builds offline from the vendored crates. WITHOUT_RUST=1
# skips it: tests skip the parity corpus and install ships Python only.
# XBPS_ARCH=x86_64-musl selects the static musl target (D20: packages are
# built only for x86_64 glibc and x86_64 musl).
ifeq ($(XBPS_ARCH),x86_64-musl)
CARGO_TARGET = --target x86_64-unknown-linux-musl
RUST_OUT = rust/target/x86_64-unknown-linux-musl/release
else
CARGO_TARGET =
RUST_OUT = rust/target/release
endif
rust-helper:
	$(CARGO) build --locked --offline --manifest-path rust/Cargo.toml

rust-helper-release:
	$(CARGO) build --locked --offline --release $(CARGO_TARGET) --manifest-path rust/Cargo.toml

ifndef WITHOUT_RUST
test check: rust-helper
install: rust-helper-release
endif

# The scdoc man pages build before they install (issue #83).
install: man

test check:
	PYTHONPATH=src $(PYTHON) -m unittest discover -s tests -t .

install:
	install -d $(LIBDIR) $(BINDIR) $(LIBEXEC) $(SVDIR)/log $(CONFDIR)/units $(SUDOERS) \
		$(DOCDIR) $(EXAMPLES)/units $(EXAMPLES)/hooks $(EXAMPLES)/autostart $(EXAMPLES)/packs $(EXAMPLES)/widgets $(SHELLDIR) $(BASHRCD) $(FISHCONF) $(MANDIR) $(MAN1DIR) $(MAN5DIR)
	install -d $(BASHCOMP) $(ZSHCOMP) $(FISHCOMP)
	install -d $(DOCDIR)/schema/ipc $(DOCDIR)/schema/cli
	find src/taema -type d -print | while read dir; do \
		rel=$${dir#src/taema}; install -d "$(LIBDIR)$$rel"; \
	done
	find src/taema -type f -name '*.py' -print | while read file; do \
		rel=$${file#src/taema/}; install -m644 "$$file" "$(LIBDIR)/$$rel"; \
	done
	install -m755 bin/taema bin/taemad bin/scoperun bin/scopekill bin/scopels bin/taema-eventd $(BINDIR)/
	install -m755 libexec/taemad-user libexec/taemad-log libexec/taema-svstop libexec/taema-hook $(LIBEXEC)/
ifdef WITHOUT_RUST
	install -m755 libexec/taema-attach.py $(LIBEXEC)/taema-attach
else
	install -m755 libexec/taema-attach $(LIBEXEC)/taema-attach
	install -m755 libexec/taema-attach.py $(LIBEXEC)/taema-attach.py
	install -m755 $(RUST_OUT)/taema-attach $(LIBEXEC)/taema-attach.rs
	install -m755 $(RUST_OUT)/taema-fast $(LIBEXEC)/taema-fast
endif
	install -m755 sv/taema/run sv/taema/finish $(SVDIR)/
	install -m755 sv/taema/log/run $(SVDIR)/log/
	install -m644 etc/taema.toml $(CONFDIR)/
	install -m644 etc/units/*.toml $(CONFDIR)/units/
	install -m440 etc/sudoers.d/taema $(SUDOERS)/
	install -m644 examples/units/*.toml $(EXAMPLES)/units/
	install -m755 examples/hooks/* $(EXAMPLES)/hooks/
	install -m644 examples/autostart/* $(EXAMPLES)/autostart/
	install -m644 examples/packs/*.toml $(EXAMPLES)/packs/
	install -m644 widgets/taema-bar/*.qml $(EXAMPLES)/widgets/
	install -m644 README.md docs/design.md ../docs/identity-resolution.md ../docs/legacy-state-migration.md ../docs/state-schema.md ../docs/upgrading-to-1.0.0.md $(DOCDIR)/
	install -m644 docs/taema-learning.7 $(MANDIR)/taema-learning.7
	install -m644 docs/taema.1 $(MAN1DIR)/taema.1
	install -m644 docs/taema-agent.1 $(MAN1DIR)/taema-agent.1
	install -m644 docs/taema.toml.5 $(MAN5DIR)/taema.toml.5
	install -m644 docs/taema.unit.5 $(MAN5DIR)/taema.unit.5
	install -m644 shell/taema.bash shell/taema.zsh shell/taema.fish $(SHELLDIR)/
	install -m644 shell/completion.bash $(BASHCOMP)/taema
	install -m644 shell/_taema $(ZSHCOMP)/_taema
	install -m644 shell/completion.fish $(FISHCOMP)/taema.fish
	install -m644 shell/taema.bash $(BASHRCD)/taema.sh
	install -m644 shell/taema.fish $(FISHCONF)/taema.fish
	install -m644 docs/vm-harness.md $(DOCDIR)/
	install -m644 schema/ipc/*.json $(DOCDIR)/schema/ipc/
	install -m644 schema/cli/*.json $(DOCDIR)/schema/cli/

# Disposable Void VM test harness (docs/vm-harness.md).  Extra flags via
# VMFLAGS, e.g. `make vm-test VMFLAGS="--allow-network --libc glibc"`.
vm-test:
	$(PYTHON) tools/vm/vmh.py run $(VMFLAGS)

vm-dry-run:
	$(PYTHON) tools/vm/vmh.py run --dry-run $(VMFLAGS)

vm-doctor:
	$(PYTHON) tools/vm/vmh.py doctor
