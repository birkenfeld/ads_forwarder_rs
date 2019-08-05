.PHONY: build install

PREFIX = /usr

build:
	cargo build --release

install: build
	install -m 755 -D target/release/ads_forwarder_rs $(DESTDIR)$(PREFIX)/bin/ads_forwarder
