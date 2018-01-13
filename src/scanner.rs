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

use std::error::Error;
use std::collections::HashMap;
use std::net::{UdpSocket, Ipv4Addr};
use std::time::Duration;

use forwarder::Beckhoff;
use util::{AmsNetId, hexdump, force_ipv4, in_same_net, FWDER_NETID,
           BECKHOFF_BC_UDP_PORT, BECKHOFF_UDP_MAGIC, BECKHOFF_UDP_PORT};


pub struct Scanner {
    pub dump: bool,
    pub if_addrs: HashMap<String, (Ipv4Addr, Ipv4Addr)>,
}

impl Scanner {
    fn scan_inner(&self, if_addr: Option<Ipv4Addr>, bh_addr: Option<Ipv4Addr>)
                  -> Result<Vec<Beckhoff>, Box<Error>> {
        let bc_scan_struct = structure!("<IHHHHHH");
        let bc_scan_result_struct = structure!("<I6x6S6x20s");
        let cx_scan_struct = structure!("<I4xI6SH4x");
        let cx_scan_result_struct = structure!("<I4xI6S6xH2x10s280xH2xBBH");

        let bind_addr = if_addr.unwrap_or([0, 0, 0, 0].into());
        let send_addr = bh_addr.unwrap_or([255, 255, 255, 255].into());
        let udp = UdpSocket::bind((bind_addr, 0))?;
        udp.set_broadcast(true)?;
        udp.set_read_timeout(Some(Duration::from_millis(500)))?;

        // scan for BCs: request 3 words from 0:21 (NetID) and 10 words from 100:4 (Name)
        let bc_msg = bc_scan_struct.pack(1, 0, 0x21, 3, 100, 4, 10).unwrap();
        udp.send_to(&bc_msg, (send_addr, BECKHOFF_BC_UDP_PORT))?;
        if self.dump {
            debug!("scan: {} bytes for BC scan", bc_msg.len());
            hexdump(&bc_msg);
        }

        // scan for CXs: "identify" operation
        let cx_msg = cx_scan_struct.pack(BECKHOFF_UDP_MAGIC, 1, &FWDER_NETID.0, 10000).unwrap();
        udp.send_to(&cx_msg, (send_addr, BECKHOFF_UDP_PORT))?;
        if self.dump {
            debug!("scan: {} bytes for CX scan", bc_msg.len());
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
            let bh_addr = force_ipv4(reply_addr.ip());
            if reply_addr.port() == BECKHOFF_BC_UDP_PORT {
                if let Ok((_, netid, name)) = bc_scan_result_struct.unpack(reply) {
                    let netid = AmsNetId::from_slice(&netid);
                    info!("scan: found {} ({}) at {}",
                          String::from_utf8_lossy(&name), netid, bh_addr);
                    beckhoffs.push(Beckhoff { if_addr: self.find_if_addr(bh_addr),
                                              is_bc: true, bh_addr, netid });
                }
            } else if let Ok(info) = cx_scan_result_struct.unpack(reply) {
                let (magic, header, netid, name_id, name, ver_id, ver_maj, ver_min, ver_patch) = info;
                if magic == BECKHOFF_UDP_MAGIC && header == 0x8000_0001 && name_id == 5 && ver_id == 3 {
                    let netid = AmsNetId::from_slice(&netid);
                    info!("scan: found {}, TwinCat {}.{}.{} ({}) at {}",
                          String::from_utf8_lossy(&name), ver_maj, ver_min, ver_patch,
                          netid, bh_addr);
                    beckhoffs.push(Beckhoff { if_addr: self.find_if_addr(bh_addr),
                                              is_bc: false, bh_addr, netid });
                }
            }
        }
        Ok(beckhoffs)
    }

    fn find_if_addr(&self, bh_addr: Ipv4Addr) -> Ipv4Addr {
        for &(if_addr, if_mask) in self.if_addrs.values() {
            if in_same_net(bh_addr, if_addr, if_mask) {
                return if_addr;
            }
        }
        panic!("Did not find local interface address for Beckhoff {}?!", bh_addr);
    }

    pub fn scan(&self, if_addr: Option<Ipv4Addr>, bh_addr: Option<Ipv4Addr>) -> Vec<Beckhoff> {
        match self.scan_inner(if_addr, bh_addr) {
            Ok(v) => v,
            Err(e) => {
                error!("error during scan: {}", e);
                Vec::new()
            }
        }
    }
}
