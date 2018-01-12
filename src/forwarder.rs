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
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket, SocketAddr, Ipv4Addr};
use std::time::Duration;
use std::mem::swap;
use std::thread;
use byteorder::{ByteOrder, LittleEndian as LE};
use channel::{self, Select, Receiver, Sender};

use Options;
use util::{AdsMessage, AmsNetId, hexdump, BECKHOFF_UDP_MAGIC, BECKHOFF_UDP_PORT,
           BECKHOFF_BC_UDP_PORT, BECKHOFF_TCP_PORT, FWDER_NETID, DUMMY_NETID};


fn spawn<F: Send + 'static + FnOnce()>(name: &str, f: F) {
    let _ = thread::Builder::new().name(name.into()).spawn(f);
}


#[derive(Clone)]
pub struct Beckhoff {
    pub if_addr: Ipv4Addr,
    pub box_addr: Ipv4Addr,
    pub netid: AmsNetId,
    pub is_bc: bool,
}

impl Beckhoff {
    /// Add a route on the Beckhoff, to `netid` via our interface address.
    fn add_route<R: AsRef<[u8]>>(&self, netid: &AmsNetId, name: R) -> FwdResult {
        if self.is_bc {
            // no routes necessary on BCs
            return Ok(());
        }
        let cx_route_struct = structure!("<I4xI6SHIHH10sHH6SHH14sHHsHH16sHHI");
        let cx_route_result_struct = structure!("<I4xI12xH2xI");
        let msg = cx_route_struct.pack(
            BECKHOFF_UDP_MAGIC, 6, &netid.0, 10000, 6,
            0x0c, 0x0a, name.as_ref(),
            0x07, 0x06, &netid.0,
            0x0d, 0x0e, b"Administrator",
            0x02, 0x01, b"",
            0x05, 0x10, format!("{}", self.if_addr).as_bytes(),
            0x09, 0x04, 1
        ).unwrap();

        let sock = UdpSocket::bind(("0.0.0.0", 0)).unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
        sock.send_to(&msg, (self.box_addr, BECKHOFF_UDP_PORT)).unwrap();

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
}


pub struct Forwarder {
    opts: Options,
    bh: Beckhoff,
}

struct Distributor {
    bh: Beckhoff,
    bh_sock: TcpStream,
    connections: Vec<ClientConn>,
    next_virtual_id: u16,
    dump: bool,
}

struct ClientConn {
    sock: TcpStream,
    peer: SocketAddr,
    chan: Receiver<Recvd>,
    client_id: AmsNetId, // master's real ID
    clients_bh_id: AmsNetId, // master's Beckhoff ID
    virtual_id: AmsNetId, // virtual ID for the temporary route
}

enum Recvd {
    Msg(AdsMessage),
    Quit,
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


impl Distributor {
    fn run(&mut self, conn_rx: Receiver<TcpStream>, bh_rx: Receiver<Recvd>) {
        let mut new_connections = Vec::new();
        loop {
            // select loop - always break after Ok replies!
            let mut sel = Select::new();
            'select: loop {
                // check for new connections
                if let Ok(sock) = sel.recv(&conn_rx) {
                    self.new_tcp_conn(sock);
                    break;
                }
                // check for replies from Beckhoff
                if let Ok(x) = sel.recv(&bh_rx) {
                    if let Recvd::Msg(mut reply) = x {
                        self.new_beckhoff_msg(reply);
                    } else {
                        error!("TCP: Beckhoff closed socket!");
                        return; // XXX quit completely or reopen!
                    }
                    break;
                }
                // check for requests from clients (AMS "masters")
                swap(&mut self.connections, &mut new_connections);
                for mut client in new_connections.drain(..) {
                    if let Ok(x) = sel.recv(&client.chan) {
                        if let Recvd::Msg(mut request) = x {
                            self.new_client_msg(request, &mut client);
                            self.connections.push(client);
                        } else { // client socket closed -- remove it
                            info!("TCP: connection from {} closed", client.peer);
                        }
                        break 'select;
                    }
                }
            }
        }
    }

    fn new_tcp_conn(&mut self, sock: TcpStream) {
        let peer = sock.peer_addr().unwrap();
        info!("TCP: new connection from {}", peer);
        let (cl_tx, cl_rx) = channel::unbounded();
        let sock2 = sock.try_clone().unwrap();
        spawn("client reader", move || read_loop(sock2, cl_tx));
        self.next_virtual_id += 1;
        let virtual_id = AmsNetId([10, 1, (self.next_virtual_id >> 8) as u8,
                                   self.next_virtual_id as u8, 1, 1]);
        info!("TCP: assigned virtual NetID {}", virtual_id);
        self.connections.push(ClientConn { sock, peer, virtual_id, chan: cl_rx,
                                           client_id: Default::default(),
                                           clients_bh_id: Default::default() });
    }

    fn new_beckhoff_msg(&mut self, mut reply: AdsMessage) {
        for client in &mut self.connections {
            if client.virtual_id == reply.dest_id() {
                reply.patch_source_id(&client.clients_bh_id);
                reply.patch_dest_id(&client.client_id);
                debug!("TCP: {} bytes Beckhoff -> Master ({})",
                       reply.length(), reply.dest_id());
                if self.dump {
                    hexdump(&reply.0);
                }
                if reply.0.len() == 0xae && reply.0[0x6e..0x74] == client.virtual_id.0 {
                    info!("TCP: mangling NetID in 'login' query");
                    reply.0[0x6e..0x74].copy_from_slice(&client.client_id.0);
                }
                client.sock.write_all(&reply.0).unwrap();
                return;
            }
        }
        if reply.dest_id().0 != [1, 1, 1, 1, 1, 1] {
            // it's not a BC keepalive
            warn!("TCP: message from Beckhoff to {} not forwarded",
                  reply.dest_id());
        }
    }

    fn new_client_msg(&self, mut request: AdsMessage, client: &mut ClientConn) {
        // first request: remember NetIDs of the requests
        if client.client_id.is_empty() {
            info!("TCP: Master {} has NetID {}",
                  client.peer, request.source_id());
            client.client_id = request.source_id();
            client.clients_bh_id = request.dest_id();

            if let Err(e) = self.bh.add_route(&client.virtual_id, "fwdclient") {
                error!("TCP: error setting up client route: {}", e);
            } else {
                info!("TCP: added client route successfully");
            }
        }
        request.patch_dest_id(&self.bh.netid);
        request.patch_source_id(&client.virtual_id);
        debug!("TCP: {} bytes Master ({}) -> Beckhoff",
               request.length(), request.source_id());
        if self.dump {
            hexdump(&request.0);
        }
        (&self.bh_sock).write_all(&request.0).unwrap();
    }
}


type FwdResult = Result<(), Box<Error>>;

impl Forwarder {
    pub fn new(opts: Options, bh: Beckhoff) -> Self {
        Forwarder { opts, bh }
    }

    fn run_keepalive(&self, sock: &TcpStream) -> FwdResult {
        let ads_msg_struct = structure!("<2xI6xH6xHHH12x");
        let netid = self.bh.netid.clone();
        let mut bh_sock = sock.try_clone()?;
        let mut msg = AdsMessage(ads_msg_struct.pack(32, // length
                                                     10000, // dest port
                                                     40001, // src port
                                                     1, // devinfo cmd
                                                     4, // it's a command
        ).unwrap());
        msg.patch_dest_id(&netid);
        msg.patch_source_id(&DUMMY_NETID);
        spawn("Keepalive", move || loop {
            thread::sleep(Duration::from_secs(1));
            let _ = bh_sock.write_all(&msg.0);
        });
        Ok(())
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
                           bh_rx: Receiver<Recvd>, bh_sock: TcpStream) {
        let mut distributor = Distributor {
            bh_sock,
            bh: self.bh.clone(),
            connections: Vec::new(),
            next_virtual_id: 0,
            dump: self.opts.verbosity >= 2,
        };
        spawn("distributor", move || distributor.run(conn_rx, bh_rx));
    }

    fn run_tcp_listener(&mut self) -> FwdResult {
        // add route to ourselves
        if let Err(e) = self.bh.add_route(&FWDER_NETID, "forwarder") {
            error!("could not add route: {}", e);
        } else {
            info!("added forwarder route to Beckhoff successfully");
        }

        // connect to Beckhoff
        let bh_sock = TcpStream::connect((self.bh.box_addr, BECKHOFF_TCP_PORT))?;
        info!("TCP: connected to Beckhoff at {}", bh_sock.peer_addr()?);
        let (bh_tx, bh_rx) = channel::unbounded();

        // start keep-alive thread
        if self.bh.is_bc {
            info!("TCP: starting keepalive request thread");
            self.run_keepalive(&bh_sock)?;
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

    pub fn run(&mut self) -> FwdResult {
        self.run_udp("UDP", BECKHOFF_UDP_PORT)?;
        self.run_udp("UDP-BC", BECKHOFF_BC_UDP_PORT)?;
        self.run_tcp_listener()?;
        Ok(())
    }
}
