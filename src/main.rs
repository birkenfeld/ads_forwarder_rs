// *****************************************************************************
//
// This program is free software; you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation; either version 2 of the License, or (at your option) any later
// version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
// details.
//
// You should have received a copy of the GNU General Public License along with
// this program; if not, write to the Free Software Foundation, Inc.,
// 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//
// Module authors:
//   Enrico Faulhaber <enrico.faulhaber@frm2.tum.de>
//   Georg Brandl <g.brandl@fz-juelich.de>
//
// *****************************************************************************

// Use the system allocator instead of jemalloc.
// This allows us to build with the i586 target on Debian 7.
#![feature(alloc_system, global_allocator, allocator_api, lookup_host)]
extern crate alloc_system;
use alloc_system::System;
#[global_allocator]
static A: System = System;

#[macro_use]
extern crate log;
extern crate mlzlog;
extern crate byteorder;
#[macro_use]
extern crate structopt;
extern crate interfaces;
extern crate itertools;
extern crate signalbool;
extern crate crossbeam_channel as channel;

use std::{net, process};
use structopt::StructOpt;

mod scanner;
mod forwarder;
mod util;

use scanner::{Scan, Scanner};

/// A forwarder for Beckhoff ADS and UDP connections.
#[derive(StructOpt)]
pub struct Options {
    #[structopt(short="F", long="forward", help="Forward connections (only scan otherwise)")]
    forward: bool,
    #[structopt(short="U", long="udp-only", help="Forward only UDP")]
    udponly: bool,
    #[structopt(short="S", long="scan-bc", help="Ignored for compatibility")]
    _ignore1: bool,
    #[structopt(short="A", long="scan-netid", help="Ignored for compatibility")]
    _ignore2: bool,
    #[structopt(short="M", long="mangle", help="Ignored for compatibility")]
    _ignore3: bool,
    #[structopt(short="v", long="verbose", help="Increase verbosity", parse(from_occurrences))]
    verbosity: u8,
    #[structopt(help="Interface, IP, AMS NetID or hostname to scan (default all interfaces)")]
    arg: Option<String>,
}

fn main() {
    let mut opts = Options::from_args();
    mlzlog::init(None::<&str>, "ads_forwarder", false, opts.verbosity >= 1, true).unwrap();

    let what = opts.arg.take().unwrap_or_default();
    let scanner = Scanner::new(opts.verbosity >= 2);

    // check out what argument was given (interface, IP address, NetID),
    // and scan for Beckhoffs an their NetIDs
    let mut beckhoffs = if scanner.if_exists(&what) {
        debug!("scanning interface {}", what);
        scanner.scan(Scan::Interface(&what))
    } else if let Ok(addr) = what.parse::<net::Ipv4Addr>() {
        debug!("scanning IP address {}", addr);
        scanner.scan(Scan::Address(addr))
    } else if let Ok(netid) = what.parse::<util::AmsNetId>() {
        debug!("scanning for AMS NetId {}", netid);
        scanner.scan(Scan::NetId(netid))
    } else if let Some(addr) = util::lookup_ipv4(&what) {
        debug!("scanning host {}", what);
        scanner.scan(Scan::Address(addr))
    } else if what.is_empty() {
        debug!("scanning everything");
        scanner.scan(Scan::Everything)
    } else {
        error!("argument must be a valid interface, IP or NetID");
        process::exit(1);
    };

    if opts.forward {
        // ensure that we have only a single Beckhoff left to talk to
        if beckhoffs.len() != 1 {
            error!("did not find exactly one Beckhoff for forwarding, exiting");
            process::exit(1);
        }
        if let Err(e) = forwarder::Forwarder::new(opts, beckhoffs.pop().unwrap()).run() {
            error!("while running forwarder: {}", e);
        }
    } else {
        if beckhoffs.is_empty() {
            info!("scan: no Beckhoff found");
        }
        info!("exiting; pass -F to forward connections")
    }
}
