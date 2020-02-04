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

use std::collections::HashMap;
use std::net::{UdpSocket, TcpStream, Ipv4Addr};
use std::time::Duration;
use anyhow::{anyhow, Context, Result};
use log::{debug, info, error};
use mlzutil::{self, bytes::hexdump};

use crate::forwarder::{Beckhoff, BhType};
use crate::util::{AmsNetId, FWDER_NETID, BECKHOFF_BC_UDP_PORT, BECKHOFF_UDP_PORT,
                  BECKHOFF_TCP_PORT, UdpMessage};


/// Determines what to scan.
pub enum Scan<'a> {
    Everything,
    Interface(&'a str),
    Address(Ipv4Addr),
    NetId(AmsNetId),
}


pub struct Scanner {
    dump: bool,
    if_addrs: HashMap<String, (Ipv4Addr, Ipv4Addr)>,
}

impl Scanner {
    pub fn new(dump: bool) -> Scanner {
        Scanner { dump, if_addrs: mlzutil::net::iface::find_ipv4_addrs() }
    }

    pub fn if_exists(&self, if_name: &str) -> bool {
        self.if_addrs.contains_key(if_name)
    }

    /// Scan the locally reachable network for Beckhoffs.
    ///
    /// If given a `Scan::Interface`, only IPs on that interface are scanned.
    /// If given a `Scan::Address`, only that IP is scanned.
    ///
    /// Returns a vector of found Beckhoffs.
    pub fn scan(&self, what: Scan) -> Vec<Beckhoff> {
        match self.scan_inner(what) {
            Ok(v) => v,
            Err(e) => {
                error!("during scan: {:#}", e);
                Vec::new()
            }
        }
    }

    fn scan_inner(&self, what: Scan) -> Result<Vec<Beckhoff>> {
        let broadcast = [255, 255, 255, 255].into();
        match what {
            Scan::Address(bh_addr) =>
                self.scan_addr([0, 0, 0, 0].into(), bh_addr, true),
            Scan::Interface(if_name) =>
                self.scan_addr(self.if_addrs[if_name].0, broadcast, false),
            Scan::Everything => {
                let mut all = Vec::new();
                for (if_name, &(if_addr, _)) in &self.if_addrs {
                    debug!("scanning interface {}", if_name);
                    all.extend(self.scan_addr(if_addr, broadcast, false)?);
                }
                Ok(all)
            }
            Scan::NetId(netid) => {
                // scan all interfaces until we found our NetID
                for (if_name, &(if_addr, _)) in &self.if_addrs {
                    debug!("scanning interface {}", if_name);
                    let bhs = self.scan_addr(if_addr, broadcast, false)
                                  .with_context(|| format!("scanning interface {}", if_name))?;
                    if let Some(bh) = bhs.into_iter().find(|bh| bh.netid == netid) {
                        return Ok(vec![bh]);
                    }
                }
                Ok(vec![])
            }
        }
    }

    fn scan_addr(&self, bind_addr: Ipv4Addr, send_addr: Ipv4Addr, single_reply: bool)
                 -> Result<Vec<Beckhoff>> {
        let udp = UdpSocket::bind((bind_addr, 0)).context("binding UDP socket")?;
        udp.set_broadcast(true)?;
        udp.set_read_timeout(Some(Duration::from_millis(500)))?;

        // scan for BCs: request 3 words from 0:33 (NetID) and 10 words from 100:4 (Name)
        let bc_msg = [1, 0, 0, 0,
                      0, 0, 33, 0, 3, 0,
                      100, 0, 4, 0, 10, 0];
        udp.send_to(&bc_msg, (send_addr, BECKHOFF_BC_UDP_PORT))
           .context("sending BC scan broadcast")?;
        debug!("scan: sending BC UDP packet");
        if self.dump {
            hexdump(&bc_msg);
        }

        // scan for CXs: "identify" operation in the UDP protocol
        let cx_msg = UdpMessage::new(UdpMessage::IDENTIFY, &FWDER_NETID, 10000).into_bytes();
        udp.send_to(&cx_msg, (send_addr, BECKHOFF_UDP_PORT))
            .context("sending CX scan broadcast")?;
        debug!("scan: sending CX UDP packet");
        if self.dump {
            hexdump(&cx_msg);
        }

        // wait for replies
        let mut beckhoffs = Vec::new();
        let mut reply = [0; 2048];
        while let Ok((len, reply_addr)) = udp.recv_from(&mut reply) {
            let reply = &reply[..len];
            if self.dump {
                info!("scan: reply from {}", reply_addr);
                hexdump(reply);
            }
            let bh_addr = mlzutil::net::unwrap_ipv4(reply_addr.ip());
            if reply_addr.port() == BECKHOFF_BC_UDP_PORT {
                if reply.len() == 42 && reply[0..4] == [1, 0, 0, 0x80] {
                    let netid = AmsNetId::from_slice(&reply[10..16]);
                    let name = &reply[22..32];
                    let name = String::from_utf8_lossy(
                        &name[..name.iter().position(|&ch| ch == 0).unwrap_or(10)]);
                    info!("scan: found {} ({}) at {}", name, netid, bh_addr);
                    beckhoffs.push(Beckhoff { if_addr: self.find_if_addr(bh_addr),
                                              typ: BhType::BC, bh_addr, netid });
                }
            } else if let Ok(msg) = UdpMessage::parse(reply, UdpMessage::IDENTIFY) {
                let name = msg.get_str(UdpMessage::HOST).unwrap_or("<???>");
                let ver = msg.get_bytes(UdpMessage::VERSION).ok_or(anyhow!("no version info"))?;
                info!("scan: found {}, TwinCat {}.{}.{} ({}) at {}",
                      name, ver[0], ver[1], ver[2] as u16 | (ver[3] as u16) << 8,
                      msg.srcid, bh_addr);
                beckhoffs.push(Beckhoff { if_addr: self.find_if_addr(bh_addr),
                                          typ: if ver[0] == 2 { BhType::CX2 } else { BhType::CX3 },
                                          bh_addr, netid: msg.srcid });
            }
            // if scanning a single address, don't wait for more replies
            if single_reply {
                break;
            }
        }
        Ok(beckhoffs)
    }

    /// Find the local address of the interface to connect to the given Beckhoff.
    fn find_if_addr(&self, bh_addr: Ipv4Addr) -> Ipv4Addr {
        // check for local IPs
        for &(if_addr, if_mask) in self.if_addrs.values() {
            if mlzutil::net::in_same_net(bh_addr, if_addr, if_mask) {
                return if_addr;
            }
        }

        // not a local IP, check by trying to connect using TCP
        match TcpStream::connect((bh_addr, BECKHOFF_TCP_PORT)).and_then(|sock| sock.local_addr()) {
            Ok(addr) => mlzutil::net::unwrap_ipv4(addr.ip()),
            _ => panic!("Did not find local address for route to Beckhoff {}", bh_addr)
        }
    }
}
