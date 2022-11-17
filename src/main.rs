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

use std::{net, process};
use log::{debug, info, error};
use structopt::StructOpt;

mod scanner;
mod forwarder;
mod util;

use crate::scanner::{Scan, Scanner};

/// A forwarder for Beckhoff ADS and UDP connections.
#[derive(StructOpt)]
pub struct Options {
    #[structopt(short="F", long="forward", help="Forward connections (only scan otherwise)")]
    forward: bool,
    #[structopt(short="U", long="udp-only", help="Forward only UDP")]
    udponly: bool,
    #[structopt(short="p", long="print", help="Print ADS headers")]
    print_ads_headers: bool,
    #[structopt(short="s", long="summarize", help="Summarize TCP packets")]
    summarize: bool,
    #[structopt(short="d", long="dump", help="Hexdump TCP and UDP packets")]
    dump: bool,
    #[structopt(short="v", long="verbose", help="Show debug log messages")]
    verbose: bool,
    #[structopt(help="Interface, IP, AMS NetID or hostname to scan (default all interfaces)")]
    target: Option<String>,
}

fn main() {
    let mut opts = Options::from_args();
    mlzlog::init(None::<&str>, "ads_forwarder",
                 mlzlog::Settings {
                     show_appname: false,
                     debug: opts.verbose,
                     ..Default::default()
                 }).unwrap();

    let what = opts.target.take().unwrap_or_default();
    let scanner = Scanner::new(opts.dump);

    // check out what argument was given (interface, IP address, NetID),
    // and scan for Beckhoffs an their NetIDs
    let mut beckhoffs = if scanner.if_exists(&what) {
        debug!("scanning interface {}", what);
        scanner.scan(Scan::Interface(&what))
    } else if let Ok(addr) = what.parse::<net::Ipv4Addr>() {
        debug!("scanning IP address {}", addr);
        scanner.scan(Scan::Address(addr))
    } else if let Ok(netid) = what.parse::<ads::AmsNetId>() {
        debug!("scanning for AMS NetId {}", netid);
        scanner.scan(Scan::NetId(netid))
    } else if let Some(addr) = mlzutil::net::lookup_ipv4(&what) {
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
            error!("while running forwarder: {:#}", e);
        }
    } else {
        if beckhoffs.is_empty() {
            info!("scan: no Beckhoff found");
        }
        info!("exiting; pass -F to forward connections")
    }
}
