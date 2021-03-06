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
use std::fmt::{self, Display};
use std::io::Write;
use std::ops::Deref;
use std::str::{self, FromStr};
use byteorder::{ByteOrder, LittleEndian as LE, ReadBytesExt, WriteBytesExt};
use itertools::Itertools;

pub const BECKHOFF_BC_UDP_PORT: u16 = 48847; // 0xBECF
pub const BECKHOFF_TCP_PORT:    u16 = 48898; // 0xBF02
pub const BECKHOFF_UDP_PORT:    u16 = 48899; // 0xBF03
pub const BECKHOFF_UDP_MAGIC:   u32 = 0x_71_14_66_03;

pub const FWDER_NETID: AmsNetId = AmsNetId([10, 1, 0, 0, 1, 1]);
pub const DUMMY_NETID: AmsNetId = AmsNetId([1, 1, 1, 1, 1, 1]);

pub type FwdResult<T> = Result<T, Box<dyn Error>>;


/// Represents an AMS NetID.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct AmsNetId(pub [u8; 6]);

impl AmsNetId {
    /// Check if the NetID is all-zero.
    pub fn is_zero(&self) -> bool {
        self.0 == [0, 0, 0, 0, 0, 0]
    }

    /// Create a NetID from a slice (which must have length 6).
    pub fn from_slice(slice: &[u8]) -> Self {
        debug_assert!(slice.len() == 6);
        let mut arr = [0; 6];
        arr.copy_from_slice(slice);
        AmsNetId(arr)
    }
}

impl FromStr for AmsNetId {
    type Err = &'static str;

    /// Parse a NetID from a string (a.b.c.d.e.f).
    ///
    /// Bytes can be missing in the end; missing bytes are substituted by 1.
    fn from_str(s: &str) -> Result<AmsNetId, &'static str> {
        let mut arr = [1; 6];
        for (i, part) in s.split('.').enumerate() {
            match (arr.get_mut(i), part.parse()) {
                (Some(loc), Ok(byte)) => *loc = byte,
                _ => return Err("invalid NetID string"),
            }
        }
        Ok(AmsNetId(arr))
    }
}

impl Display for AmsNetId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0.iter().format("."))
    }
}


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

    pub fn new(dstid: &AmsNetId, dstport: u16, srcid: &AmsNetId, srcport: u16,
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
        AmsNetId::from_slice(&self.0[6..12])
    }

    pub fn source_id(&self) -> AmsNetId {
        AmsNetId::from_slice(&self.0[14..20])
    }

    pub fn patch_dest_id(&mut self, id: &AmsNetId) {
        self.0[6..12].copy_from_slice(&id.0);
    }

    pub fn patch_source_id(&mut self, id: &AmsNetId) {
        self.0[14..20].copy_from_slice(&id.0);
    }
}


/// Represents a message in the UDP protocol used by CX Beckhoffs.
pub struct UdpMessage<T: Deref<Target=[u8]>> {
    pub srcid: AmsNetId,
    pub srcport: u16,
    pub op: u32,
    items: Vec<(u16, usize, usize)>,
    data: T,
}

impl UdpMessage<Vec<u8>> {
    // operations
    pub const IDENTIFY: u32 = 1;
    pub const ADD_ROUTE: u32 = 6;

    // designators
    pub const STATUS: u16 = 1;
    pub const PASSWORD: u16 = 2;
    pub const VERSION: u16 = 3;
    pub const HOST: u16 = 5;
    pub const NETID: u16 = 7;
    pub const OPTIONS: u16 = 9;
    pub const ROUTENAME: u16 = 12;
    pub const USERNAME: u16 = 13;

    pub fn new(op: u32, srcid: &AmsNetId, srcport: u16) -> UdpMessage<Vec<u8>> {
        UdpMessage { op, srcid: *srcid, srcport,
                     items: Vec::with_capacity(8), data: Vec::with_capacity(128) }
    }

    pub fn add_bytes(&mut self, desig: u16, data: &[u8]) {
        self.data.write_u16::<LE>(desig).unwrap();
        let start = self.data.len();
        self.data.write_u16::<LE>(data.len() as u16).unwrap();
        self.data.write_all(data).unwrap();
        self.items.push((desig, start, self.data.len()));
    }

    pub fn add_str(&mut self, desig: u16, data: &str) {
        self.data.write_u16::<LE>(desig).unwrap();
        let start = self.data.len();
        self.data.write_u16::<LE>(data.len() as u16 + 1).unwrap();
        self.data.write_all(data.as_bytes()).unwrap();
        self.data.write_u8(0).unwrap();
        self.items.push((desig, start, self.data.len()));
    }

    pub fn add_u32(&mut self, desig: u16, data: u32) {
        self.data.write_u16::<LE>(desig).unwrap();
        let start = self.data.len();
        self.data.write_u16::<LE>(4).unwrap();
        self.data.write_u32::<LE>(data).unwrap();
        self.items.push((desig, start, self.data.len()));
    }

    pub fn parse(mut data: &[u8], op: u32) -> FwdResult<UdpMessage<&[u8]>> {
        if data.read_u32::<LE>()? != BECKHOFF_UDP_MAGIC {
            Err("magic not recognized")?;
        }
        if data.read_u32::<LE>()? != 0 {
            Err("zero bytes missing")?;
        }
        if data.read_u32::<LE>()? != op | 0x8000_0000 {
            Err("operation acknowledge missing")?;
        }
        let srcid = AmsNetId::from_slice(&data[..6]);
        data = &data[6..];
        let srcport = data.read_u16::<LE>()?;
        let nitems = data.read_u32::<LE>()?;

        let mut items = Vec::with_capacity(nitems as usize);
        {
            let mut data_ptr = &data[..];
            let mut pos = 4;
            while let Ok(desig) = data_ptr.read_u16::<LE>() {
                let len = data_ptr.read_u16::<LE>()? as usize;
                items.push((desig, pos, pos + len));
                pos += len + 4;
                data_ptr = &data_ptr[len..];
            }
        }
        Ok(UdpMessage { op, srcid, srcport, data, items })
    }
}

impl<T: Deref<Target=[u8]>> UdpMessage<T> {
    fn map_desig<'a, O, F>(&'a self, desig: u16, map: F) -> Option<O>
        where F: Fn(&'a [u8]) -> Option<O>
    {
        self.items.iter().find(|item| item.0 == desig)
                         .and_then(|&(_, i, j)| map(&self.data[i..j]))
    }

    pub fn get_bytes(&self, desig: u16) -> Option<&[u8]> {
        self.map_desig(desig, Some)
    }

    pub fn get_str(&self, desig: u16) -> Option<&str> {
        self.map_desig(desig, |b| str::from_utf8(b).ok())
    }

    pub fn get_u32(&self, desig: u16) -> Option<u32> {
        self.map_desig(desig, |mut b| b.read_u32::<LE>().ok())
    }

    pub fn into_bytes(self) -> Vec<u8> {
        let mut v = Vec::with_capacity(self.data.len() + 24);
        for &n in &[BECKHOFF_UDP_MAGIC, 0, self.op] {
            v.write_u32::<LE>(n).unwrap();
        }
        v.write_all(&self.srcid.0).unwrap();
        v.write_u16::<LE>(self.srcport).unwrap();
        v.write_u32::<LE>(self.items.len() as u32).unwrap();
        v.extend_from_slice(&self.data);
        v
    }
}
