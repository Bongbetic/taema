# taema: install layout for Void Linux. Paths are fixed to /usr and /etc; use DESTDIR to stage.
DESTDIR ?=
PYTHON  ?= python3

PY_FILES  = $(wildcard src/taema/*.py)
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

.PHONY: all test check install

all:
	@:

test check:
	PYTHONPATH=src $(PYTHON) -m unittest discover -s tests -t .

install:
	install -d $(LIBDIR) $(BINDIR) $(LIBEXEC) $(SVDIR)/log $(CONFDIR)/units $(SUDOERS) \
		$(DOCDIR) $(EXAMPLES)/units $(EXAMPLES)/hooks $(SHELLDIR) $(BASHRCD) $(FISHCONF)
	install -m644 $(PY_FILES) $(LIBDIR)/
	install -m755 bin/taema bin/scoperun bin/scopekill bin/scopels $(BINDIR)/
	install -m755 libexec/taema-attach libexec/taemad-user libexec/taemad-log libexec/taema-svstop libexec/taema-hook $(LIBEXEC)/
	install -m755 sv/taema/run sv/taema/finish $(SVDIR)/
	install -m755 sv/taema/log/run $(SVDIR)/log/
	install -m644 etc/taema.toml $(CONFDIR)/
	install -m644 etc/units/*.toml $(CONFDIR)/units/
	install -m440 etc/sudoers.d/taema $(SUDOERS)/
	install -m644 examples/units/*.toml $(EXAMPLES)/units/
	install -m755 examples/hooks/* $(EXAMPLES)/hooks/
	install -m644 README.md docs/design.md $(DOCDIR)/
	install -m644 shell/taema.bash shell/taema.zsh shell/taema.fish $(SHELLDIR)/
	install -m644 shell/taema.bash $(BASHRCD)/taema.sh
	install -m644 shell/taema.fish $(FISHCONF)/taema.fish
