ADS forwarder
=============

Forwards and multiplexes Beckhoff ADS connections and scans/mangles NetIDs.

What it is good for
-------------------

ADS is the protocol Beckhoff PLCs and IPCs use for communication with TwinCAT or
custom control applications.

The ADS forwarder is meant to be used in the following two situations:

* Multiple applications want to connect from a single machine to the same PLC.

  (Since Beckhoff allows only one TCP connection from each IP, this is only
  possible using a router/multiplexer, which this tool provides.)

* The ADS target (usually a PLC) is in another network, behind a "gateway"
  computer.

The forwarder listens to the ADS TCP communication port (48898) on the local
machine and applications can connect there instead of the actual PLC.  UDP
messages (on port 48899) are also forwarded.

How to build/install
--------------------

* Install Rust and Cargo (e.g. via rustup).  Version 1.48+ is required.
* Call `cargo build --release` to build.
* The executable is in `target/release/ads_forwarder`.
* The `Makefile` is very simple instructions and simply installs this to
  `/usr/bin`.

Usage notes
-----------

```
USAGE:
    ads_forwarder_rs [FLAGS] [target]

FLAGS:
    -d, --dump         Hexdump TCP and UDP packets
    -F, --forward      Forward connections (only scan otherwise)
    -h, --help         Prints help information
    -p, --print        Print ADS headers
    -s, --summarize    Summarize TCP packets
    -U, --udp-only     Forward only UDP
    -V, --version      Prints version information
    -v, --verbose      Show debug log messages

ARGS:
    <target>    Interface, IP, AMS NetID or hostname to scan (default all interfaces)
```

The important option is `-F`: by default the tool only scans for available PLCs.
Without `target`, all interfaces of the system are scanned (using UDP
broadcast).  Specify an interface, IP/hostname or NetID to disambiguate.

Principle of operation
----------------------

In order to achieve its goal, the forwarder does not need a route to itself on
the target PLC; it will set routes on the fly (this currently needs the default
password to be unchanged).

For each client that connects to the forwarder, the forwarder invents a unique
NetID and sets a route to itself for this NetID.  In this manner, ADS replies
can be distributed to their original requester.
