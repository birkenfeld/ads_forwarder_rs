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

use std::io::Write;

use ads::AmsNetId;
use byteorder::{ByteOrder, LittleEndian as LE, WriteBytesExt};

pub const BECKHOFF_BC_UDP_PORT: u16 = 48847; // 0xBECF
pub const BECKHOFF_TCP_PORT:    u16 = ads::PORT; // 0xBF02
pub const BECKHOFF_UDP_PORT:    u16 = ads::UDP_PORT; // 0xBF03

pub const FWDER_NETID: AmsNetId = AmsNetId::new(10, 1, 0, 0, 1, 1);
pub const DUMMY_NETID: AmsNetId = AmsNetId::new(1, 1, 1, 1, 1, 1);


/// Represents an ADS message.
pub struct AdsMessage(pub Vec<u8>);

impl AdsMessage {
    pub fn from_bytes(msg: Vec<u8>) -> AdsMessage {
        let msg = AdsMessage(msg);
        // todo: could expand checks here
        assert!(msg.length() == msg.0.len());
        msg
    }

    pub const DEVINFO: u16 = 1;
    pub const WRITE: u16 = 3;

    pub fn new(dstid: AmsNetId, dstport: u16, srcid: AmsNetId, srcport: u16,
               cmd: u16, data: &[u8]) -> AdsMessage {
        let mut v = vec![0; 2];
        v.write_u32::<LE>(32 + data.len() as u32).unwrap();
        v.write_all(&dstid.0).unwrap();
        v.write_u16::<LE>(dstport).unwrap();
        v.write_all(&srcid.0).unwrap();
        v.write_u16::<LE>(srcport).unwrap();
        v.write_u16::<LE>(cmd).unwrap();
        v.write_u16::<LE>(4).unwrap();
        v.write_u32::<LE>(data.len() as u32).unwrap();
        v.write_u64::<LE>(0).unwrap(); // Error-code + Invoke-ID
        v.write_all(data).unwrap();
        AdsMessage(v)
    }

    pub fn length(&self) -> usize {
        6 + LE::read_u32(&self.0[2..6]) as usize
    }

    pub fn dest_id(&self) -> AmsNetId {
        AmsNetId::from_slice(&self.0[6..12]).unwrap()
    }

    pub fn source_id(&self) -> AmsNetId {
        AmsNetId::from_slice(&self.0[14..20]).unwrap()
    }

    pub fn patch_dest_id(&mut self, id: AmsNetId) {
        self.0[6..12].copy_from_slice(&id.0);
    }

    pub fn patch_source_id(&mut self, id: AmsNetId) {
        self.0[14..20].copy_from_slice(&id.0);
    }

    /// Print a summary of the request/response to stdout.
    pub fn summarize(&self) -> bool {
        let cmd = LE::read_u16(&self.0[22..]);

        if cmd == 8 {
            // ignore notifications
            return false;
        }

        let dport = LE::read_u16(&self.0[12..]);
        let stf = LE::read_u16(&self.0[24..]);
        let mut err = LE::read_u32(&self.0[30..]);
        let inv = LE::read_u32(&self.0[34..]);

        let cmdname = match cmd {
            1 => "DevInfo",
            2 => "Read ",
            3 => "Write",
            4 => "GetState",
            5 => "WriteControl",
            6 => "AddNotif",
            7 => "DelNotif",
            8 => "Notification",
            9 => "ReadWrite",
            _ => "???",
        };
        let reply = stf & 1 != 0;
        
        let prefix = format!("{}[{}]{} {:5} {}",
                             if reply { "<-" } else { "--" },
                             inv, if reply { "--" } else { "->" },
                             dport, cmdname);
        if !reply {
            match cmd {
                2 | 3 | 6 => if self.0.len() >= 50 {
                    let igrp = LE::read_u32(&self.0[38..]);
                    let ioff = LE::read_u32(&self.0[42..]);
                    let len  = LE::read_u32(&self.0[46..]);
                    println!("{}: {:#x}:{:#x} {} bytes", prefix, igrp, ioff, len);
                }
                9 => if self.0.len() >= 54 {
                    let igrp = LE::read_u32(&self.0[38..]);
                    let ioff = LE::read_u32(&self.0[42..]);
                    let rlen = LE::read_u32(&self.0[46..]);
                    let wlen = LE::read_u32(&self.0[50..]);
                    println!("{}: {:#x}:{:#x} {}/{} bytes", prefix, igrp, ioff, rlen, wlen);
                }
                _ => println!("{}", prefix)
            }
        } else {
            if err == 0 && self.0.len() >= 42 && LE::read_u32(&self.0[38..]) != 0 {
                err = LE::read_u32(&self.0[38..]);
            }
            if err != 0 {
                let msg: ads::Result<()> = ads::errors::ads_error("ERROR", err);
                println!("{}: {}\n", prefix, msg.unwrap_err());
            } else {
                // println!("{}: no error\n", prefix);
            }
        }

        true  // also dump if wanted
    }
}
