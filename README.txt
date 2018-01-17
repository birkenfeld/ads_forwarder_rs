Beckhoff ADS forwarder
======================

Forwards ADS connections and scans/mangles NetIDs.

How to build
------------

New enough OSs:

* `rustup update nightly`
* `cargo +nightly build --release`

32-bit Debian 7 for Geode:

* `rustup update nightly`
* `rustup target add i586-unknown-linux-gnu`
* `cargo +nightly build --release --target=i586-unknown-linux-gnu`
