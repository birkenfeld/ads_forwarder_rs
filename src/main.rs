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
use clap::Parser;
use atty::Stream;

mod scanner;
mod forwarder;
mod util;

use ads::{AmsNetId};
use crate::scanner::{Scan, Scanner};


/// A forwarder for Beckhoff ADS and UDP connections.
#[derive(Parser)]
#[clap(author, version, about)]
pub struct Options {
    #[clap(short='F', long="forward", help="Forward connections (only scan otherwise)")]
    forward: bool,
    #[clap(short='U', long="udp-only", help="Forward only UDP")]
    udponly: bool,
    #[clap(short='s', long="summarize", help="Summarize TCP packets")]
    summarize: bool,
    #[clap(short='S', long="single-ams-net-id", help="Use only one AMS Net ID towards Beckhoff")]
    single_ams_net_id: bool,
    #[clap(short='d', long="dump", help="Hexdump TCP and UDP packets")]
    dump: bool,
    #[clap(short='v', long="verbose", help="Show debug log messages")]
    verbose: bool,
    #[clap(long="local-ams-net-id")]
    local_ams_net_id: Option<AmsNetId>,
    #[clap(help="Interface, IP, AMS NetID or hostname to scan (default all interfaces)")]
    target: Option<String>,
}

fn main() {
    let mut opts = Options::from_args();
    mlzlog::init(None::<&str>, "ads_forwarder",
                 mlzlog::Settings {
                     show_appname: false,
                     stdout_color: atty::is(Stream::Stdout),
                     debug: opts.verbose,
                     ..Default::default()
                 }).unwrap();

    let what = opts.target.take().unwrap_or_default();
    let scanner = Scanner::new(opts.dump);

    // check out what argument was given (interface, IP address, NetID),
    // and scan for Beckhoffs an their NetIDs
    let mut beckhoffs = if scanner.if_exists(&what) {
        debug!("scanning interface {what}");
        scanner.scan(Scan::Interface(&what))
    } else if let Ok(addr) = what.parse::<net::Ipv4Addr>() {
        debug!("scanning IP address {addr}");
        scanner.scan(Scan::Address(addr))
    } else if let Ok(netid) = what.parse::<ads::AmsNetId>() {
        debug!("scanning for AMS NetId {netid}");
        scanner.scan(Scan::NetId(netid))
    } else if let Some(addr) = mlzutil::net::lookup_ipv4(&what) {
        debug!("scanning host {what}");
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
        if let Err(err) = forwarder::Forwarder::new(opts, beckhoffs.pop().unwrap()).run() {
            error!("while running forwarder: {err:#}");
        }
    } else {
        if beckhoffs.is_empty() {
            info!("scan: no Beckhoff found");
        }
        info!("exiting; pass -F to forward connections")
    }
}
