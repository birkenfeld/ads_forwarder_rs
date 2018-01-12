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

mod scanner;
mod forwarder;
mod util;

use std::net::Ipv4Addr;
use std::process;
use std::collections::HashMap;
use structopt::StructOpt;


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
    mlzlog::init(".", "ads_forwarder", false, opts.verbosity >= 1, true).unwrap();

    // determine IPv4 addresses of all interfaces in the system
    let if_addrs = interfaces::Interface::get_all().unwrap().into_iter().filter_map(|iface| {
        util::ipv4_addr(&iface.addresses).map(|addr| (iface.name.clone(), addr))
    }).collect::<HashMap<_, _>>();

    // check out what argument was given (interface, IP address, NetID),
    // and scan for boxes an their NetIDs
    let scanner = scanner::Scanner { dump: opts.verbosity >= 2, if_addrs };
    let mut boxes = if let Some(&(ifaddr, _)) = scanner.if_addrs.get(&opts.arg) {
        debug!("using interface {}", opts.arg);
        scanner.scan(Some(ifaddr), None)
    } else if let Ok(addr) = opts.arg.parse::<Ipv4Addr>() {
        debug!("using IP address {}", addr);
        scanner.scan(None, Some(addr))
    } else if let Ok(netid) = opts.arg.parse::<util::AmsNetId>() {
        debug!("using AMS NetId {}", netid);
        scanner.scan(None, None).into_iter().filter(|b| b.netid == netid).collect()
    } else if opts.arg.is_empty() {
        debug!("scanning everything");
        scanner.scan(None, None)
    } else {
        error!("argument must be a valid interface, IP or NetID");
        process::exit(1);
    };

    if opts.forward {
        // ensure that we have only a single box left to talk to
        if boxes.len() != 1 {
            error!("did not find exactly one Beckhoff, exiting");
            process::exit(1);
        }
        if let Err(e) = forwarder::Forwarder::new(opts, boxes.pop().unwrap()).run() {
            error!("while running forwarder: {}", e);
        }
    }
}
