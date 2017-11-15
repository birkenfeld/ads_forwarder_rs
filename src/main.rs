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

use std::error::Error;
use std::io::{Read, Write};
use std::fmt::{self, Display};
use std::net::{TcpListener, TcpStream, UdpSocket, SocketAddr, IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::time::Duration;
use std::{process, thread};
use std::collections::HashMap;
use channel::{Select, Sender, Receiver};
use byteorder::{ByteOrder, LittleEndian as LE};
use itertools::Itertools;
use structopt::StructOpt;

const BECKHOFF_BC_UDP_PORT: u16 = 48847; // 0xBECF
const BECKHOFF_TCP_PORT: u16  = 48898; // 0xBF02
const BECKHOFF_UDP_PORT: u16  = 48899; // 0xBF03
const BECKHOFF_UDP_MAGIC: u32 = 0x71146603;
const DUMMY_NETID: &[u8] = &[10, 0, 0, 1, 1, 1];

type FwdResult = Result<(), Box<Error>>;

#[derive(Clone, PartialEq, Eq, Default)]
struct AmsNetId([u8; 6]);

impl AmsNetId {
    fn is_empty(&self) -> bool {
        self.0 == [0, 0, 0, 0, 0, 0]
    }

    fn from_slice(slice: &[u8]) -> Self {
        debug_assert!(slice.len() == 6);
        let mut arr = [0; 6];
        arr.copy_from_slice(slice);
        AmsNetId(arr)
    }
}

impl FromStr for AmsNetId {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<AmsNetId, &'static str> {
        // Not given parts of NetID default to "1"
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

struct AdsMessage(Vec<u8>);

impl AdsMessage {
    fn new(msg: Vec<u8>) -> AdsMessage {
        let msg = AdsMessage(msg);
        // XXX expand checks
        assert!(msg.length() == msg.0.len());
        msg
    }
    fn length(&self) -> usize {
        6 + LE::read_u32(&self.0[2..6]) as usize
    }
    fn dest_id(&self) -> AmsNetId {
        AmsNetId::from_slice(&self.0[6..12])
    }
    fn source_id(&self) -> AmsNetId {
        AmsNetId::from_slice(&self.0[14..20])
    }
    fn patch_dest_id(&mut self, id: &AmsNetId) {
        self.0[6..12].copy_from_slice(&id.0);
    }
    fn patch_source_id(&mut self, id: &AmsNetId) {
        self.0[14..20].copy_from_slice(&id.0);
    }
}


fn spawn<F: Send + 'static + FnOnce()>(name: &str, f: F) {
    let _ = thread::Builder::new().name(name.into()).spawn(f);
}

fn printable(ch: &u8) -> char {
    if *ch >= 32 && *ch <= 127 { *ch as char } else { '.' }
}

fn hexdump(mut data: &[u8]) {
    let mut addr = 0;
    while !data.is_empty() {
        let (line, rest) = data.split_at(data.len().min(16));
        println!("{:#06x}: {:02x}{} | {}", addr,
                 line.iter().format(" "),
                 (0..16 - line.len()).map(|_| "   ").format(""),
                 line.iter().map(printable).format(""));
        addr += 16;
        data = rest;
    }
    println!();
}

fn in_same_net<T: Into<u32>>(addr1: T, addr2: T, netmask: T) -> bool {
    let (addr1, addr2, netmask) = (addr1.into(), addr2.into(), netmask.into());
    addr1 & netmask == addr2 & netmask
}

fn force_ipv4(addr: IpAddr) -> Ipv4Addr {
    match addr {
        IpAddr::V6(_) => panic!("IPv4 address required"),
        IpAddr::V4(ip) => ip
    }
}

fn ipv4_addr(addresses: &[interfaces::Address]) -> Option<(Ipv4Addr, Ipv4Addr)> {
    addresses.iter().find(|ad| ad.kind == interfaces::Kind::Ipv4)
                    .map(|ad| (force_ipv4(ad.addr.unwrap().ip()),
                               force_ipv4(ad.mask.unwrap().ip())))
}


#[derive(Clone)]
struct Beckhoff {
    if_addr: Ipv4Addr,
    box_addr: Ipv4Addr,
    netid: AmsNetId,
    is_bc: bool,
}


struct Scanner {
    dump: bool,
    if_addrs: HashMap<String, (Ipv4Addr, Ipv4Addr)>,
}

impl Scanner {
    fn scan_inner(&self, if_addr: Option<Ipv4Addr>, box_addr: Option<Ipv4Addr>)
                  -> Result<Vec<Beckhoff>, Box<Error>> {
        let bc_scan_struct = structure!("<IHHHHHH");
        let bc_scan_result_struct = structure!("<I6x6S6x20s");
        let cx_scan_struct = structure!("<I4xI6SH4x");
        let cx_scan_result_struct = structure!("<I4xI6S6xH2x10s280xH2xBBH");

        let bind_addr = if_addr.unwrap_or([0, 0, 0, 0].into());
        let send_addr = box_addr.unwrap_or([255, 255, 255, 255].into());
        let udp = UdpSocket::bind((bind_addr, 0))?;
        udp.set_broadcast(true)?;
        udp.set_read_timeout(Some(Duration::from_millis(500)))?;

        // scan for BCs: request 3 words from 0:21 (NetID) and 10 words from 100:4 (Name)
        let bc_msg = bc_scan_struct.pack(1, 0, 0x21, 3, 100, 4, 10).unwrap();
        udp.send_to(&bc_msg, (send_addr, BECKHOFF_BC_UDP_PORT))?;
        if self.dump {
            info!("scan: {} bytes for BC scan", bc_msg.len());
            hexdump(&bc_msg);
        }

        // scan for CXs: "identify" operation
        let cx_msg = cx_scan_struct.pack(BECKHOFF_UDP_MAGIC, 1, DUMMY_NETID, 10000).unwrap();
        udp.send_to(&cx_msg, (send_addr, BECKHOFF_UDP_PORT))?;
        if self.dump {
            info!("scan: {} bytes for CX scan", bc_msg.len());
            hexdump(&cx_msg);
        }

        // wait for replies
        let mut boxes = Vec::new();
        let mut reply = [0; 2048];
        while let Ok((len, bh_addr)) = udp.recv_from(&mut reply) {
            let reply = &reply[..len];
            if self.dump {
                info!("scan: reply from {}", bh_addr);
                hexdump(reply);
            }
            let box_addr = force_ipv4(bh_addr.ip());
            if bh_addr.port() == BECKHOFF_BC_UDP_PORT {
                if let Ok((_, netid, name)) = bc_scan_result_struct.unpack(reply) {
                    let netid = AmsNetId::from_slice(&netid);
                    info!("scan: found {} ({}) at {}",
                          String::from_utf8_lossy(&name), netid, box_addr);
                    boxes.push(Beckhoff { if_addr: self.find_if_addr(box_addr),
                                          is_bc: true, box_addr, netid });
                }
            } else if let Ok(info) = cx_scan_result_struct.unpack(reply) {
                let (magic, header, netid, name_id, name, ver_id, ver_maj, ver_min, ver_patch) = info;
                if magic == BECKHOFF_UDP_MAGIC && header == 0x8000_0001 && name_id == 5 && ver_id == 3 {
                    let netid = AmsNetId::from_slice(&netid);
                    info!("scan: found {}, TwinCat {}.{}.{} ({}) at {}",
                          String::from_utf8_lossy(&name), ver_maj, ver_min, ver_patch,
                          netid, box_addr);
                    boxes.push(Beckhoff { if_addr: self.find_if_addr(box_addr),
                                          is_bc: false, box_addr, netid });
                }
            }
        }
        Ok(boxes)
    }

    fn find_if_addr(&self, box_addr: Ipv4Addr) -> Ipv4Addr {
        for &(if_addr, if_mask) in self.if_addrs.values() {
            if in_same_net(box_addr, if_addr, if_mask) {
                return if_addr;
            }
        }
        panic!("Did not find interface address for local box {}?!", box_addr);
    }

    fn scan(&self, if_addr: Option<Ipv4Addr>, box_addr: Option<Ipv4Addr>) -> Vec<Beckhoff> {
        match self.scan_inner(if_addr, box_addr) {
            Ok(v) => v,
            Err(e) => {
                error!("error during scan: {}", e);
                Vec::new()
            }
        }
    }
}


struct ClientConn {
    sock: TcpStream,
    peer: SocketAddr,
    chan: Receiver<Recvd>,
    client_id: AmsNetId, // master's real ID
    clients_bh_id: AmsNetId, // master's Beckhoff ID
    virtual_id: AmsNetId, // virtual ID for the temporary route
}

struct Forwarder {
    opts: Options,
    bh: Beckhoff,
}

enum Recvd {
    Msg(AdsMessage),
    Quit,
}

fn keepalive(mut sock: TcpStream, netid: AmsNetId) {
    let ads_msg_struct = structure!("<2xI6xH6xHHH12x");
    let mut msg = AdsMessage(ads_msg_struct.pack(32, // length
                                                 10000, // dest port
                                                 40001, // src port
                                                 1, // devinfo cmd
                                                 4, // it's a command
    ).unwrap());
    msg.patch_dest_id(&netid);
    msg.patch_source_id(&AmsNetId([1, 1, 1, 1, 1, 1]));
    loop {
        thread::sleep(Duration::from_secs(1));
        let _ = sock.write_all(&msg.0);
    }
}

fn read_loop(mut sock: TcpStream, chan: Sender<Recvd>) {
    loop {
        let mut message = Vec::with_capacity(100);
        // read size
        message.resize(6, 0);
        if sock.read_exact(&mut message).is_err() {
            let _ = chan.send(Recvd::Quit);
            return;
        }
        let size = LE::read_u32(&message[2..6]);
        // read rest of message
        message.resize(size as usize + 6, 0);
        if sock.read_exact(&mut message[6..]).is_err() {
            let _ = chan.send(Recvd::Quit);
            return;
        }
        // send message to distributor
        if chan.send(Recvd::Msg(AdsMessage::new(message))).is_err() {
            return;
        }
    }
}

impl Forwarder {
    fn new(opts: Options, bh: Beckhoff) -> Self {
        Forwarder { opts, bh }
    }

    fn run_udp(&self, name: &'static str, port: u16) -> FwdResult {
        let sock = UdpSocket::bind(("0.0.0.0", port))?;
        sock.set_broadcast(true)?;
        info!("{}: bound to {}", name, sock.local_addr()?);

        let bh_ip = self.bh.box_addr;
        let dump = self.opts.verbosity >= 2;
        spawn("UDP", move || {
            let mut master = "0.0.0.0".parse().unwrap();
            let mut buf = [0; 3072];
            loop {
                let (len, addr) = sock.recv_from(&mut buf).unwrap();
                if addr.ip() != bh_ip {
                    if addr.ip() != master {
                        info!("{}: Master is now {}", name, addr);
                        master = addr.ip();
                    }
                    info!("{}: {} bytes Master -> Beckhoff", name, len);
                    if dump {
                        hexdump(&buf[..len]);
                    }
                    sock.send_to(&buf[..len], (bh_ip, port)).unwrap();
                } else {
                    info!("{}: {} bytes Beckhoff -> Master", name, len);
                    if dump {
                        hexdump(&buf[..len]);
                    }
                    sock.send_to(&buf[..len], (master, port)).unwrap();
                }
            }
        });
        Ok(())
    }

    fn run_tcp_distributor(&mut self, conn_rx: Receiver<TcpStream>,
                           bh_rx: Receiver<Recvd>, mut bh_sock: TcpStream) {
        let mut connections = Vec::<ClientConn>::new();
        let mut cleanup = None;
        let mut next_virtual_id: u16 = 0;
        let dump = self.opts.verbosity >= 2;
        let bh = self.bh.clone();

        spawn("distributor", move || loop {
            // channel select loop - always break after Ok() replies!
            let mut sel = Select::new();
            'select: loop {
                // cleanup connections
                if let Some(peer) = cleanup {
                    connections.retain(|client| client.peer != peer);
                }
                // check for new connections
                if let Ok(sock) = sel.recv(&conn_rx) {
                    let peer = sock.peer_addr().unwrap();
                    info!("TCP: new connection from {}", peer);
                    let (cl_tx, cl_rx) = channel::unbounded();
                    let mut sock2 = sock.try_clone().unwrap();
                    spawn("client reader", move || read_loop(sock2, cl_tx));
                    next_virtual_id += 1;
                    let virtual_id = AmsNetId([10, 1, (next_virtual_id >> 8) as u8,
                                               next_virtual_id as u8, 1, 1]);
                    info!("TCP: assigned virtual NetID {}", virtual_id);
                    connections.push(ClientConn { sock, peer, virtual_id, chan: cl_rx,
                                                  client_id: Default::default(),
                                                  clients_bh_id: Default::default() });
                    break;
                }
                // check for replies from Beckhoff
                if let Ok(x) = sel.recv(&bh_rx) {
                    if let Recvd::Msg(mut reply) = x {
                        for client in &mut connections {
                            if client.virtual_id == reply.dest_id() {
                                reply.patch_source_id(&client.clients_bh_id);
                                reply.patch_dest_id(&client.client_id);
                                debug!("TCP: {} bytes Beckhoff -> Master ({})",
                                       reply.length(), reply.dest_id());
                                if dump {
                                    hexdump(&reply.0);
                                }
                                if reply.0.len() == 0xae && reply.0[0x6e..0x74] == client.virtual_id.0 {
                                    info!("TCP: mangling NetID in 'login' query");
                                    reply.0[0x6e..0x74].copy_from_slice(&client.client_id.0);
                                }
                                client.sock.write_all(&reply.0).unwrap();
                                break 'select;
                            }
                        }
                        if reply.dest_id().0 != [1, 1, 1, 1, 1, 1] {
                            // it's not a BC keepalive
                            warn!("TCP: message from Beckhoff to {} not forwarded",
                                  reply.dest_id());
                        }
                    } else { // BH socket closed -- quit
                        error!("TCP: Beckhoff closed socket!");
                        return; // XXX reopen!
                    }
                    break;
                }
                // check for requests from clients (AMS "masters")
                for client in &mut connections {
                    if let Ok(x) = sel.recv(&client.chan) {
                        if let Recvd::Msg(mut request) = x {
                            // first request: remember NetIDs of the request
                            if client.client_id.is_empty() {
                                info!("TCP: Master {} has NetID {}",
                                      client.peer, request.source_id());
                                client.client_id = request.source_id();
                                client.clients_bh_id = request.dest_id();

                                if !bh.is_bc {
                                    if let Err(e) = Self::add_route(&bh, &client.virtual_id, "fwdclient") {
                                        error!("TCP: error setting up route: {}", e);
                                    } else {
                                        info!("TCP: added back route successfully");
                                    }
                                }
                            }
                            request.patch_dest_id(&bh.netid);
                            request.patch_source_id(&client.virtual_id);
                            debug!("TCP: {} bytes Master ({}) -> Beckhoff",
                                   request.length(), request.source_id());
                            if dump {
                                hexdump(&request.0);
                            }
                            bh_sock.write_all(&request.0).unwrap();
                        } else { // client socket closed -- remove it
                            info!("TCP: connection from {} closed", client.peer);
                            cleanup = Some(client.peer);
                        }
                        break 'select;
                    }
                }
            }
        });
    }

    fn add_route<R: AsRef<[u8]>>(bh: &Beckhoff, netid: &AmsNetId, name: R) -> FwdResult {
        let cx_route_struct = structure!("<I4xI6SHIHH10sHH6SHH14sHHsHH12sHHI");
        let cx_route_result_struct = structure!("<I4xI12xH2xI");
        let msg = cx_route_struct.pack(
            BECKHOFF_UDP_MAGIC, 6, &netid.0, 10000, 6,
            0x0c, 0x0a, name.as_ref(),
            0x07, 0x06, &netid.0,
            0x0d, 0x0e, b"Administrator",
            0x02, 0x01, b"",
            0x05, 0x0c, format!("{}", bh.if_addr).as_bytes(),
            0x09, 0x04, 1
        ).unwrap();

        let sock = UdpSocket::bind(("0.0.0.0", 0)).unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
        sock.send_to(&msg, (bh.box_addr, BECKHOFF_UDP_PORT)).unwrap();

        let mut reply = [0; 2048];
        let (len, _) = sock.recv_from(&mut reply)?;
        let (magic, header, res_id, res) = cx_route_result_struct.unpack(&reply[..len])?;
        if magic != BECKHOFF_UDP_MAGIC {
            return Err("invalid magic in reply".into());
        }
        if header != 0x8000_0006 || res_id != 0x1 || res != 0 {
            return Err("invalid result in reply".into());
        }
        Ok(())
    }

    fn run_tcp_listener(&mut self) -> FwdResult {
        // connect to Beckhoff
        let bh_sock = TcpStream::connect((self.bh.box_addr, BECKHOFF_TCP_PORT))?;
        info!("TCP: connected to Beckhoff at {}", bh_sock.peer_addr()?);
        let (bh_tx, bh_rx) = channel::unbounded();

        // start keep-alive thread
        if self.bh.is_bc {
            let netid = self.bh.netid.clone();
            let bh_sock2 = bh_sock.try_clone()?;
            info!("TCP: starting keepalive request thread");
            spawn("Keepalive", move || keepalive(bh_sock2, netid));
        }

        // listen for incoming connections
        let srv_sock = TcpListener::bind(("0.0.0.0", BECKHOFF_TCP_PORT))?;
        info!("TCP: bound to {}", srv_sock.local_addr()?);
        let (conn_tx, conn_rx) = channel::unbounded();

        // send BH replies from socket to distributor
        let bh_sock2 = bh_sock.try_clone()?;
        spawn("BH reader", move || read_loop(bh_sock2, bh_tx));

        // run distributor
        self.run_tcp_distributor(conn_rx, bh_rx, bh_sock);

        // main loop: send new client sockets to distributor
        for conn in srv_sock.incoming() {
            conn_tx.send(conn?).unwrap();
        }

        Ok(())
    }

    fn run(&mut self) -> FwdResult {
        // add route to ourselves
        if !self.bh.is_bc {
            if let Err(e) = Self::add_route(&self.bh, &AmsNetId([10, 1, 0, 0, 1, 1]), "forwarder") {
                error!("could not add route: {}", e);
            } else {
                info!("added forwarder route to Beckhoff successfully");
            }
        }

        self.run_udp("UDP", BECKHOFF_UDP_PORT)?;
        self.run_udp("UDP2", BECKHOFF_BC_UDP_PORT)?;
        self.run_tcp_listener()?;
        Ok(())
    }
}

#[derive(StructOpt)]
struct Options {
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

    let if_addrs = interfaces::Interface::get_all().unwrap().into_iter().filter_map(|iface| {
        ipv4_addr(&iface.addresses).map(|addr| (iface.name.clone(), addr))
    }).collect::<HashMap<_, _>>();

    // check out what argument was given (interface, IP address, NetID)
    let scanner = Scanner { dump: opts.verbosity >= 2, if_addrs };
    let mut boxes = if let Some(&(ifaddr, _)) = scanner.if_addrs.get(&opts.arg) {
        debug!("using interface {}", opts.arg);
        scanner.scan(Some(ifaddr), None)
    } else if let Ok(addr) = opts.arg.parse::<Ipv4Addr>() {
        debug!("using IP address {}", addr);
        scanner.scan(None, Some(addr))
    } else if let Ok(netid) = opts.arg.parse::<AmsNetId>() {
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
        // ensure that we have a single box left to talk to
        if boxes.len() != 1 {
            error!("did not find exactly one Beckhoff, exiting");
            process::exit(1);
        }
        if let Err(e) = Forwarder::new(opts, boxes.pop().unwrap()).run() {
            error!("while running forwarder: {}", e);
        }
    }
}
