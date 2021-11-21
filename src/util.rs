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
}
