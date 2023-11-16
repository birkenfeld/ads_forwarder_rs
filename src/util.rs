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

use std::convert::TryInto;
use std::io::Write;

use ads::AmsNetId;
use byteorder::{ByteOrder, LittleEndian as LE, WriteBytesExt};
use log::debug;
use mlzutil::bytes::hexdump;

pub const BECKHOFF_BC_UDP_PORT: u16 = 48847; // 0xBECF
pub const BECKHOFF_TCP_PORT:    u16 = ads::PORT; // 0xBF02
pub const BECKHOFF_UDP_PORT:    u16 = ads::UDP_PORT; // 0xBF03

pub const FWDER_NETID: AmsNetId = AmsNetId::new(10, 1, 0, 0, 1, 1);
pub const DUMMY_NETID: AmsNetId = AmsNetId::new(1, 1, 1, 1, 1, 1);

pub const DEVINFO:      u16 = 1;
pub const READ:         u16 = 2;
pub const WRITE:        u16 = 3;
pub const GETSTATE:     u16 = 4;
pub const WRITECONTROL: u16 = 5;
pub const ADDNOTIF:     u16 = 6;
pub const DELNOTIF:     u16 = 7;
pub const NOTIF:        u16 = 8;
pub const READWRITE:    u16 = 9;

#[derive(Debug)]
pub enum InOutClientBH {
    InFrmClnt,
    OutToClnt,
    InFrmBeck,
    OutToBeck,
}

/// Represents an ADS message.
pub struct AdsMessage(pub Vec<u8>);

#[derive(Debug, Copy, Clone)]
#[derive(PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AddNotifReqData {
    pub dest_port:    u16, // The ADS port on the PLC where the notification is
    pub index_group:  u32, // Notification data follow here
    pub index_offset: u32,
    pub length:       u32,
    pub trans_mode:   u32,
    pub max_delay:    u32,
    pub cycle_time:   u32,
    pub res:          [u8; 16],
}

impl AdsMessage {
    pub fn from_bytes(msg: Vec<u8>) -> AdsMessage {
        let msg = AdsMessage(msg);
        // todo: could expand checks here
        assert!(msg.get_length() == msg.0.len());
        msg
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(dstid: AmsNetId, dstport: u16, srcid: AmsNetId, srcport: u16,
               cmd: u16, reply: bool, invoke_id: u32, data: &[u8]) -> AdsMessage {
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
        if self.0.len() >= 45 && self.get_cmd() == ADDNOTIF && LE::read_u32(&self.0[38..]) == 0 {
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
        let mut debug_printed = false;
        let dport = self.get_dest_port();
        let stf = self.get_state_flags();
        let mut err = self.get_error_code();
        let inv = self.get_invoke_id();
        let cmd = self.get_cmd();
        let cmdname = match cmd {
            DEVINFO => "DevInfo",
            READ => "Read ",
            WRITE => "Write",
            GETSTATE => "GetState",
            WRITECONTROL => "WriteControl",
            ADDNOTIF => "AddNotif",
            DELNOTIF => "DelNotif",
            NOTIF => "Notification",
            READWRITE => "ReadWrite",
            _ => "???",
        };
        let reply = stf & 1 != 0;

        let prefix = format!("{in_out_bh_clnt:?} {} {}:{}[{inv:#08x}]->{}:{}  {cmdname}",
                             if reply { "Rep" } else { "Req" },
                             self.get_source_id(), self.get_source_port(),
                             self.get_dest_id(), self.get_dest_port());
        if cmd == NOTIF && self.0.len() >= 45 {
            let pay_len = LE::read_u32(&self.0[26..]);
            let error = LE::read_u32(&self.0[30..]);
            let invoke_id = LE::read_u32(&self.0[34..]);
            let nots_len = LE::read_u32(&self.0[38..]);
            let num_stamps = LE::read_u32(&self.0[42..]);
            let timestamp = LE::read_u64(&self.0[46..]);
            let num_samples = LE::read_u32(&self.0[54..]);
            debug!("{prefix}: pay_len={pay_len} error={error} invoke_id={invoke_id} \
                    nots_len={nots_len} num_stamps={num_stamps} timestamp={timestamp} \
                    num_samples={num_samples}");
            debug_printed = true;
            let mut sample_idx = 0;
            let mut read_index = 58;
            // Hand-made loop
            while sample_idx < num_samples {
                let handle = LE::read_u32(&self.0[read_index..]);
                let sample_size = LE::read_u32(&self.0[read_index+4..]);
                let sample_data = &self.0[read_index+8..read_index+8+sample_size as usize];
                debug!("{prefix}: sample_idx={sample_idx} handle={handle} read_index={read_index} \
                        sample_size={sample_size} sample_data={sample_data:?}");
                read_index += 8 + sample_size as usize;
                sample_idx += 1;
            }
        }

        if !reply {
            match cmd {
                READ | WRITE => if self.0.len() >= 50 {
                    let igrp = LE::read_u32(&self.0[38..]);
                    let ioff = LE::read_u32(&self.0[42..]);
                    let len  = LE::read_u32(&self.0[46..]);
                    debug!("{prefix}: {igrp:#x}:{ioff:#x} {len} bytes");
                    debug_printed = true;
                }
                ADDNOTIF => if self.0.len() >= 61 {
                    let invoke_id = LE::read_u32(&self.0[34..]);
                    let igrp = LE::read_u32(&self.0[38..]);
                    let ioff = LE::read_u32(&self.0[42..]);
                    let len  = LE::read_u32(&self.0[46..]);
                    let transmode = LE::read_u32(&self.0[50..]);
                    let maxdelay = LE::read_u32(&self.0[54..]);
                    let cycletime = LE::read_u32(&self.0[58..]);
                    debug!("{prefix}: {igrp:#x}:{ioff:#x} {len} bytes transmode={transmode} \
                            maxdelay={maxdelay} cycletime={cycletime} invoke_id={invoke_id}");
                    debug_printed = true;
                }
                DELNOTIF => if self.0.len() >= 42 {
                    let invoke_id = LE::read_u32(&self.0[34..]);
                    let handle = LE::read_u32(&self.0[38..]);
                    debug!("{prefix}: dport={dport} handle={handle} invoke_id={invoke_id}");
                    debug_printed = true;
                }
                READWRITE => if self.0.len() >= 54 {
                    let igrp = LE::read_u32(&self.0[38..]);
                    let ioff = LE::read_u32(&self.0[42..]);
                    let rlen = LE::read_u32(&self.0[46..]);
                    let wlen = LE::read_u32(&self.0[50..]);
                    debug!("{prefix}: {igrp:#x}:{ioff:#x} {rlen}/{wlen} bytes");
                    debug_printed = true;
                }
                _ => {}
            }
        } else {
            match cmd {
                ADDNOTIF => if self.0.len() >= 45 {
                    let invoke_id = LE::read_u32(&self.0[34..]);
                    let result = LE::read_u32(&self.0[38..]);
                    let handle = LE::read_u32(&self.0[42..]);
                    debug!("{prefix}: result={result} handle={handle} invoke_id={invoke_id}");
                    debug_printed = true;
                }
                NOTIF => {}
                _ => {
                    let invoke_id = LE::read_u32(&self.0[34..]);
                    if err == 0 && self.0.len() >= 42 && LE::read_u32(&self.0[38..]) != 0 {
                        err = LE::read_u32(&self.0[38..]);
                    }
                    if err != 0 {
                        let msg: ads::Result<()> = ads::errors::ads_error("ERROR", err);
                        debug!("{prefix}: {} invoke_id={invoke_id}\n", msg.unwrap_err());
                    } else {
                        debug!("{prefix}: no error invoke_id={invoke_id}\n");
                    }
                    debug_printed = true;
                }
            }
        }
        if ! debug_printed {
            debug!("{in_out_bh_clnt:?} {} {}:{}[{inv:#08x}]->{}:{}  {cmdname}",
                   if reply { "Rep" } else { "Req" },
                   self.get_source_id(), self.get_source_port(),
                   self.get_dest_id(), self.get_dest_port());
        }

        if do_hex {
            hexdump(&self.0);
        }
    }

    pub fn get_add_notif_req_data(&self) -> Option<AddNotifReqData> {
        if self.0.len() >= 78 && self.get_cmd() == ADDNOTIF {
            Some(AddNotifReqData {
                dest_port:    self.get_dest_port(),
                index_group:  LE::read_u32(&self.0[38..]),
                index_offset: LE::read_u32(&self.0[42..]),
                length:       LE::read_u32(&self.0[46..]),
                trans_mode:   LE::read_u32(&self.0[50..]),
                max_delay:    LE::read_u32(&self.0[54..]),
                cycle_time:   LE::read_u32(&self.0[58..]),
                res:          self.0[62..78].try_into().unwrap(),
            })
        } else {
            None
        }
    }
}


// https://infosys.beckhoff.com/english.php?content=../content/1033/tc3_ads_intro/115883019.html
pub struct NotifData {
    data: Vec<u8>,
}

impl NotifData {
    pub fn new() -> Self {
        Self {
            data: vec![4, 0, 0, 0, 0, 0, 0, 0],  // length and number of stamps
        }
    }

    pub fn add_stamp(&mut self, timestamp: u64, samples: &[(u32, &[u8])]) {
        self.data.write_u64::<LE>(timestamp).unwrap();
        self.data.write_u32::<LE>(samples.len() as u32).unwrap();
        for sample in samples {
            self.data.write_u32::<LE>(sample.0).unwrap();
            self.data.write_u32::<LE>(sample.1.len() as u32).unwrap();
            self.data.extend_from_slice(sample.1);
        }
        // update length and number of stamps
        let new_len = self.data.len() as u32 - 4;
        let new_count = LE::read_u32(&self.data[4..]) + 1;
        LE::write_u32(&mut self.data, new_len);
        LE::write_u32(&mut self.data[4..], new_count);
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }
}
