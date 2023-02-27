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
use mlzutil::{bytes::hexdump};

pub const BECKHOFF_BC_UDP_PORT: u16 = 48847; // 0xBECF
pub const BECKHOFF_TCP_PORT:    u16 = ads::PORT; // 0xBF02
pub const BECKHOFF_UDP_PORT:    u16 = ads::UDP_PORT; // 0xBF03

pub const FWDER_NETID: AmsNetId = AmsNetId::new(10, 1, 0, 0, 1, 1);
pub const DUMMY_NETID: AmsNetId = AmsNetId::new(1, 1, 1, 1, 1, 1);

#[derive(Debug)]
pub enum InOutClientBH {
    InFrmClnt,
    OutToClnt,
    InFrmBeck,
    OutToBeck,
}

/// Represents an ADS message.
pub struct AdsMessage(pub Vec<u8>);

#[derive(Debug)]
#[derive(Copy,Clone)]
//#[derive(Eq, Hash)]
#[derive(PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AddNotifReqData {
    pub dest_port:    u16, // The ADS port on the PLC where the notification is
    pub index_group:  u32, // Notification data follow here
    pub index_offset: u32,
    pub length:       u32,
    pub trans_mode:   u32,
    pub max_delay:    u32,
    pub cycle_time:   u32,
    pub res_0:         u8,
    pub res_1:         u8,
    pub res_2:         u8,
    pub res_3:         u8,
    pub res_4:         u8,
    pub res_5:         u8,
    pub res_6:         u8,
    pub res_7:         u8,
    pub res_8:         u8,
    pub res_9:         u8,
    pub res_10:        u8,
    pub res_11:        u8,
    pub res_12:        u8,
    pub res_13:        u8,
    pub res_14:        u8,
    pub res_15:        u8,
}

impl AdsMessage {
    pub fn from_bytes(msg: Vec<u8>) -> AdsMessage {
        let msg = AdsMessage(msg);
        // todo: could expand checks here
        assert!(msg.get_length() == msg.0.len());
        msg
    }

    pub const DEVINFO: u16 = 1;
    pub const WRITE: u16 = 3;
    //pub const DELNOTIF: u16 = 7;

    pub fn new(dstid: AmsNetId, dstport: u16, srcid: AmsNetId, srcport: u16,
               cmd: u16, data: &[u8], reply: bool, invoke_id: u32) -> AdsMessage {
        let mut v = vec![0; 2];
        v.write_u32::<LE>(32 + data.len() as u32).unwrap();
        v.write_all(&dstid.0).unwrap();
        v.write_u16::<LE>(dstport).unwrap();
        v.write_all(&srcid.0).unwrap();
        v.write_u16::<LE>(srcport).unwrap();
        v.write_u16::<LE>(cmd).unwrap();
        v.write_u16::<LE>(4 | (reply as u16)).unwrap();
        v.write_u32::<LE>(data.len() as u32).unwrap();
        v.write_u32::<LE>(0).unwrap(); // Error-code
        v.write_u32::<LE>(invoke_id).unwrap();
        v.write_all(data).unwrap();
        AdsMessage(v)
    }

    pub fn get_length(&self) -> usize {
        6 + LE::read_u32(&self.0[2..6]) as usize
    }

    pub fn get_dest_id(&self) -> AmsNetId {
        AmsNetId::from_slice(&self.0[6..12]).unwrap()
    }

    pub fn get_dest_port(&self) -> u16 {
        LE::read_u16(&self.0[12..14])
    }

    pub fn get_source_id(&self) -> AmsNetId {
        AmsNetId::from_slice(&self.0[14..20]).unwrap()
    }

    pub fn get_source_port(&self) -> u16 {
        LE::read_u16(&self.0[20..22])
    }

    pub fn get_cmd(&self) -> u16 {
        LE::read_u16(&self.0[22..24])
    }

    pub fn get_state_flags(&self) -> u16 {
        LE::read_u16(&self.0[24..26])
    }

    pub fn get_error_code(&self) -> u32 {
        LE::read_u32(&self.0[30..34]) as u32
    }

    pub fn get_invoke_id(&self) -> u32 {
        LE::read_u32(&self.0[34..38]) as u32
    }

    pub fn get_add_notification_reply_handle(&self) -> Option<u32> {
        if self.0.len() >= 45 && self.get_cmd() == 6 && LE::read_u32(&self.0[38..]) == 0 {
            Some::<u32>(LE::read_u32(&self.0[42..]))
        } else {
            None
        }
    }

    pub fn patch_dest_id(&mut self, id: AmsNetId) {
        self.0[6..12].copy_from_slice(&id.0);
    }

    pub fn patch_dest_port(&mut self, port: u16) {
        LE::write_u16(&mut self.0[12..14], port)
    }

    pub fn patch_source_id(&mut self, id: AmsNetId) {
        self.0[14..20].copy_from_slice(&id.0);
    }
    pub fn patch_source_port(&mut self, port: u16) {
        LE::write_u16(&mut self.0[20..22], port)
    }

    pub fn patch_invoke_id(&mut self, invoke_id: u32) {
        LE::write_u32(&mut self.0[34..38], invoke_id)
    }

    /// Print a summary of the request/response to stdout.
    pub fn summarize(&self, in_out_bh_clnt: InOutClientBH, do_hex: bool) {
        let dport = self.get_dest_port();
        let stf = self.get_state_flags();
        let mut err = self.get_error_code();
        let inv = self.get_invoke_id();
        let cmd = self.get_cmd();
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

       let prefix = format!("{:?} {} {}:{}[{:#08x}]->{}:{}  {}",
                            in_out_bh_clnt, if reply { "Rep" } else { "Req" },
                            self.get_source_id(), self.get_source_port(),
                            inv,
                            self.get_dest_id(), self.get_dest_port(),
                            cmdname);
        match cmd {
            8 => {
                if self.0.len() >= 45 {
                    let pay_len = LE::read_u32(&self.0[26..]);
                    let error = LE::read_u32(&self.0[30..]);
                    let invoke_id = LE::read_u32(&self.0[34..]);
                    let nots_len = LE::read_u32(&self.0[38..]);
                    let num_stamps = LE::read_u32(&self.0[42..]);
                    let timestamp = LE::read_u64(&self.0[46..]);
                    let num_samples = LE::read_u32(&self.0[54..]);
                    println!("{}: pay_len={} error=={} invoke_id={} nots_len={} num_stamps={} timestamp={} num_samples={}",
                             prefix, pay_len, error, invoke_id, nots_len, num_stamps, timestamp, num_samples);
                    let mut sample_idx = 0;
                    let mut read_index = 58;
                    // Hand-made loop
                    while sample_idx < num_samples {
                        let handle = LE::read_u32(&self.0[read_index..]);
                        let sample_size = LE::read_u32(&self.0[read_index+4..]);
                        let sample_data = &self.0[read_index+8..read_index+8+sample_size as usize];
                        println!("{}: sample_idx={} handle={} read_index={} sample_size={} sample_data={:?}",
                                 prefix, sample_idx, handle, read_index, sample_size, sample_data);
                        read_index = read_index + 8 + sample_size as usize;
                        sample_idx = sample_idx + 1;
                    }
                }
            }
            _ => {}
        }
        if !reply {
            match cmd {
                2 | 3  => if self.0.len() >= 50 {
                    let igrp = LE::read_u32(&self.0[38..]);
                    let ioff = LE::read_u32(&self.0[42..]);
                    let len  = LE::read_u32(&self.0[46..]);
                    println!("{}: {:#x}:{:#x} {} bytes", prefix, igrp, ioff, len);
                }
                6 => if self.0.len() >= 61 {
                    let igrp = LE::read_u32(&self.0[38..]);
                    let ioff = LE::read_u32(&self.0[42..]);
                    let len  = LE::read_u32(&self.0[46..]);
                    let transmode = LE::read_u32(&self.0[50..]);
                    let maxdelay = LE::read_u32(&self.0[54..]);
                    let cycletime = LE::read_u32(&self.0[58..]);
                    println!("{}: {:#x}:{:#x} {} bytes transmode={} maxdelay={} cycletime={}", prefix, igrp, ioff, len, transmode, maxdelay, cycletime);
                }
                7 => if self.0.len() >= 42 {
                    let handle = LE::read_u32(&self.0[38..]);
                    println!("{}: dport={} handle={}", prefix, dport, handle);
                }
                8 => {}
                9 => if self.0.len() >= 54 {
                    let igrp = LE::read_u32(&self.0[38..]);
                    let ioff = LE::read_u32(&self.0[42..]);
                    let rlen = LE::read_u32(&self.0[46..]);
                    let wlen = LE::read_u32(&self.0[50..]);
                    println!("{}: {:#x}:{:#x} {}/{} bytes", prefix, igrp, ioff, rlen, wlen);
                }
                _ => println!("REQXXX {}", prefix)
            }
        } else {
            match cmd {
                6 => if self.0.len() >= 45 {
                    let result = LE::read_u32(&self.0[38..]);
                    let handle = LE::read_u32(&self.0[42..]);
                    println!("{}: result={} handle={}", prefix, result, handle);
                }
                8 => {}
                _ => {
                    if err == 0 && self.0.len() >= 42 && LE::read_u32(&self.0[38..]) != 0 {
                        err = LE::read_u32(&self.0[38..]);
                    }
                    if err != 0 {
                        let msg: ads::Result<()> = ads::errors::ads_error("ERROR", err);
                        println!("{}: {}\n", prefix, msg.unwrap_err());
                    } else {
                        println!("{}: no error\n", prefix);
                    }
                }
            }
        }
        if do_hex == true {
            hexdump(&self.0);
        }
    }
    pub fn get_add_notif_req_data(&self) -> Option<AddNotifReqData> {
        if self.0.len() >= 78 && self.get_cmd() == 6 {
            let dest_port = self.get_dest_port();
            let igrp = LE::read_u32(&self.0[38..]);
            let ioff = LE::read_u32(&self.0[42..]);
            let len  = LE::read_u32(&self.0[46..]);
            let transmode = LE::read_u32(&self.0[50..]);
            let maxdelay = LE::read_u32(&self.0[54..]);
            let cycletime = LE::read_u32(&self.0[58..]);
            let add_notif_req_data = AddNotifReqData {
                dest_port:    dest_port,
                index_group:  igrp,
                index_offset: ioff,
                length:       len,
                trans_mode:   transmode,
                max_delay:    maxdelay,
                cycle_time:   cycletime,
                res_0:        self.0[62],
                res_1:        self.0[63],
                res_2:        self.0[64],
                res_3:        self.0[65],
                res_4:        self.0[66],
                res_5:        self.0[67],
                res_6:        self.0[68],
                res_7:        self.0[69],
                res_8:        self.0[70],
                res_9:        self.0[71],
                res_10:       self.0[72],
                res_11:       self.0[73],
                res_12:       self.0[74],
                res_13:       self.0[75],
                res_14:       self.0[76],
                res_15:       self.0[77]  };
            Some::<AddNotifReqData> ( add_notif_req_data )
        } else {
            None
        }
    }
}



