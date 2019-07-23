.PHONY: build install

build:
	cargo build --release

install: build
	install -m 755 -D target/release/ads_forwarder_rs $(DESTDIR)/usr/sbin/ads_forwarder
