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

#[macro_use]
extern crate log;
extern crate mlzlog;
extern crate byteorder;
extern crate structopt;
extern crate interfaces;
extern crate itertools;
extern crate crossbeam_channel as channel;
#[macro_use]
extern crate structopt_derive;
#[macro_use]
extern crate structure;

use std::{net, process};
use structopt::StructOpt;

mod scanner;
mod forwarder;
mod util;

use scanner::{Scan, Scanner};

/// Used to define and parse command line options.
#[derive(StructOpt)]
pub struct Options {
    #[structopt(short="F", long="forward", help="Forward connections (only scan otherwise)")]
    forward: bool,
    #[structopt(short="S", long="scan-bc", help="Ignored for compatibility")]
    _ignore1: bool,
    #[structopt(short="A", long="scan-netid", help="Ignored for compatibility")]
    _ignore2: bool,
    #[structopt(short="M", long="mangle", help="Ignored for compatibility")]
    _ignore3: bool,
    #[structopt(short="v", long="verbose", help="Increase verbosity")]
    verbosity: u64,
    #[structopt(help="Interface, IP or AMS NetID to forward to")]
    arg: String,
}

fn main() {
    let opts = Options::from_args();
    mlzlog::init(None::<&str>, "ads_forwarder", false, opts.verbosity >= 1, true).unwrap();

    // check out what argument was given (interface, IP address, NetID),
    // and scan for Beckhoffs an their NetIDs
    let scanner = Scanner::new(opts.verbosity >= 2);
    let mut beckhoffs = if scanner.if_exists(&opts.arg) {
        debug!("scanning interface {}", opts.arg);
        scanner.scan(Scan::Interface(&opts.arg))
    } else if let Ok(addr) = opts.arg.parse::<net::Ipv4Addr>() {
        debug!("scanning IP address {}", addr);
        scanner.scan(Scan::Address(addr))
    } else if let Ok(netid) = opts.arg.parse::<util::AmsNetId>() {
        debug!("scanning for AMS NetId {}", netid);
        // scan all possible Beckhoffs and filter out the matching one
        scanner.scan(Scan::Everything).into_iter().filter(|b| b.netid == netid).collect()
    } else if opts.arg.is_empty() {
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
    }
}
