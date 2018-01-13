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
use mlzlog;

use Options;
use util::{AdsMessage, AmsNetId, hexdump, BECKHOFF_UDP_MAGIC, BECKHOFF_UDP_PORT,
           BECKHOFF_BC_UDP_PORT, BECKHOFF_TCP_PORT, FWDER_NETID, DUMMY_NETID};


fn spawn<F: Send + 'static + FnOnce()>(name: &str, f: F) {
    let _ = thread::Builder::new().name(name.into()).spawn(f);
}


#[derive(Clone)]
pub struct Beckhoff {
    pub if_addr: Ipv4Addr,
    pub bh_addr: Ipv4Addr,
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

        let sock = UdpSocket::bind(("0.0.0.0", 0))?;
        sock.set_read_timeout(Some(Duration::from_millis(500)))?;
        sock.send_to(&msg, (self.bh_addr, BECKHOFF_UDP_PORT))?;

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
    connections: Vec<ClientConn>,
    next_virtual_id: u16,
    dump: bool,
}

struct ClientConn {
    sock: TcpStream,
    peer: SocketAddr,
    chan: Receiver<Recvd>,
    client_id: AmsNetId, // client's real ID
    clients_bh_id: AmsNetId, // client thinks this is Beckhoff's ID
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
    fn connect(&mut self) -> Result<(TcpStream, Receiver<Recvd>), Box<Error>> {
        // connect to Beckhoff
        let bh_sock = TcpStream::connect((self.bh.bh_addr, BECKHOFF_TCP_PORT))?;
        info!("connected to Beckhoff at {}", bh_sock.peer_addr()?);
        let (bh_tx, bh_rx) = channel::unbounded();

        // start keep-alive thread
        if self.bh.is_bc {
            info!("starting BC keepalive thread");
            self.run_keepalive(&bh_sock)?;
        }

        // send BH replies from socket to distributor
        let bh_sock2 = bh_sock.try_clone()?;
        spawn("BH reader", move || read_loop(bh_sock2, bh_tx));
        Ok((bh_sock, bh_rx))
    }

    fn run_keepalive(&self, sock: &TcpStream) -> FwdResult {
        let mut bh_sock = sock.try_clone()?;
        let ads_msg_struct = structure!("<2xI6xH6xHHH12x");
        let mut msg = AdsMessage(ads_msg_struct.pack(32, // length
                                                     10000, // dest port
                                                     40001, // src port
                                                     1, // devinfo cmd
                                                     4, // it's a command
        ).unwrap());
        msg.patch_dest_id(&self.bh.netid);
        msg.patch_source_id(&DUMMY_NETID);
        spawn("keepalive", move || loop {
            mlzlog::set_thread_prefix("TCP: ".into());
            thread::sleep(Duration::from_secs(1));
            if bh_sock.write_all(&msg.0).is_err() {
                debug!("keepalive thread exiting");
                break;
            }
        });
        Ok(())
    }

    fn run(&mut self, conn_rx: Receiver<TcpStream>) {
        mlzlog::set_thread_prefix("TCP: ".into());
        loop {
            match self.connect() {
                Ok((bh_sock, bh_chan)) => self.handle(&conn_rx, bh_sock, bh_chan),
                Err(e) => {
                    error!("error on connection to Beckhoff: {}", e);
                    thread::sleep(Duration::from_secs(1));
                }
            }
        }
    }

    fn handle(&mut self, conn_rx: &Receiver<TcpStream>, mut bh_sock: TcpStream, bh_chan: Receiver<Recvd>) {
        let mut new_connections = Vec::new();
        loop {
            // select loop - always break after Ok replies!
            let mut sel = Select::new();
            'select: loop {
                // check for new connections
                if let Ok(sock) = sel.recv(&conn_rx) {
                    if let Err(e) = self.new_tcp_conn(sock) {
                        warn!("error handling new client connection: {}", e);
                    }
                    break 'select;
                }
                // check for replies from Beckhoff
                if let Ok(x) = sel.recv(&bh_chan) {
                    if let Recvd::Msg(mut reply) = x {
                        self.new_beckhoff_msg(reply);
                    } else {
                        error!("Beckhoff closed socket!");
                        // this will close all client connections too
                        return;
                    }
                    break 'select;
                }
                // check for requests from clients (AMS "masters")
                swap(&mut self.connections, &mut new_connections);
                for mut client in new_connections.drain(..) {
                    if let Ok(x) = sel.recv(&client.chan) {
                        if let Recvd::Msg(mut request) = x {
                            self.new_client_msg(request, &mut client, &mut bh_sock);
                            self.connections.push(client);
                        } else { // client socket closed -- remove it
                            info!("connection from {} closed", client.peer);
                        }
                        break 'select;
                    }
                }
            }
        }
    }

    fn new_tcp_conn(&mut self, sock: TcpStream) -> FwdResult {
        let peer = sock.peer_addr()?;
        info!("new connection from {}", peer);
        let (cl_tx, cl_rx) = channel::unbounded();
        let sock2 = sock.try_clone()?;
        spawn("client reader", move || read_loop(sock2, cl_tx));
        self.next_virtual_id += 1;
        let virtual_id = AmsNetId([10, 1, (self.next_virtual_id >> 8) as u8,
                                   self.next_virtual_id as u8, 1, 1]);
        info!("assigned virtual NetID {}", virtual_id);
        self.connections.push(ClientConn { sock, peer, virtual_id, chan: cl_rx,
                                           client_id: Default::default(),
                                           clients_bh_id: Default::default() });
        Ok(())
    }

    fn new_beckhoff_msg(&mut self, mut reply: AdsMessage) {
        for client in &mut self.connections {
            if client.virtual_id == reply.dest_id() {
                reply.patch_source_id(&client.clients_bh_id);
                reply.patch_dest_id(&client.client_id);
                debug!("{} bytes Beckhoff -> client ({})",
                       reply.length(), reply.dest_id());
                if self.dump {
                    hexdump(&reply.0);
                }
                if reply.0.len() == 0xae && reply.0[0x6e..0x74] == client.virtual_id.0 {
                    info!("mangling NetID in 'login' query");
                    reply.0[0x6e..0x74].copy_from_slice(&client.client_id.0);
                }
                // if the socket is closed, the next read attempt will return Quit
                // and the client will be dropped, so only log send failures here
                if let Err(e) = client.sock.write_all(&reply.0) {
                    warn!("error forwarding reply to client: {}", e);
                }
                return;
            }
        }
        if reply.dest_id() != DUMMY_NETID {
            // it's not a BC keepalive
            warn!("message from Beckhoff to {} not forwarded", reply.dest_id());
        }
    }

    fn new_client_msg(&self, mut request: AdsMessage, client: &mut ClientConn, bh_sock: &mut TcpStream) {
        // first request: remember NetIDs of the requests
        if client.client_id.is_empty() {
            info!("client {} has NetID {}",
                  client.peer, request.source_id());
            client.client_id = request.source_id();
            client.clients_bh_id = request.dest_id();

            if let Err(e) = self.bh.add_route(&client.virtual_id, "fwdclient") {
                error!("error setting up client route: {}", e);
            } else {
                info!("added client route successfully");
            }
        }
        request.patch_dest_id(&self.bh.netid);
        request.patch_source_id(&client.virtual_id);
        debug!("{} bytes client ({}) -> Beckhoff",
               request.length(), request.source_id());
        if self.dump {
            hexdump(&request.0);
        }
        // if the socket is closed, the next read attempt will return Quit
        // and the connection will be reopened
        if let Err(e) = bh_sock.write_all(&request.0) {
            warn!("error forwarding request to Beckhoff: {}", e);
        }
    }
}


type FwdResult = Result<(), Box<Error>>;

impl Forwarder {
    pub fn new(opts: Options, bh: Beckhoff) -> Self {
        Forwarder { opts, bh }
    }

    fn run_udp(&self, name: &'static str, port: u16) -> FwdResult {
        let sock = UdpSocket::bind(("0.0.0.0", port))?;
        sock.set_broadcast(true)?;
        info!("{}: bound to {}", name, sock.local_addr()?);

        let bh_ip = self.bh.bh_addr;
        let dump = self.opts.verbosity >= 2;
        spawn(name, move || {
            mlzlog::set_thread_prefix(format!("{}: ", name));
            let mut active_client = "0.0.0.0".parse().unwrap();
            let mut buf = [0; 3072];
            loop {
                if let Ok((len, addr)) = sock.recv_from(&mut buf) {
                    if addr.ip() != bh_ip {
                        if addr.ip() != active_client {
                            info!("active client is now {}", addr);
                            active_client = addr.ip();
                        }
                        info!("{} bytes client -> Beckhoff", len);
                        if dump {
                            hexdump(&buf[..len]);
                        }
                        if let Err(e) = sock.send_to(&buf[..len], (bh_ip, port)) {
                            warn!("error forwarding request to Beckhoff: {}", e);
                        }
                    } else {
                        info!("{} bytes Beckhoff -> client", len);
                        if dump {
                            hexdump(&buf[..len]);
                        }
                        if let Err(e) = sock.send_to(&buf[..len], (active_client, port)) {
                            warn!("error forwarding request to client: {}", e);
                        }
                    }
                }
            }
        });
        Ok(())
    }

    fn run_tcp_distributor(&mut self, conn_rx: Receiver<TcpStream>) {
        let mut distributor = Distributor {
            bh: self.bh.clone(),
            connections: Vec::new(),
            next_virtual_id: 0,
            dump: self.opts.verbosity >= 2,
        };
        spawn("distributor", move || distributor.run(conn_rx));
    }

    fn run_tcp_listener(&mut self) -> FwdResult {
        // add route to ourselves
        if let Err(e) = self.bh.add_route(&FWDER_NETID, "forwarder") {
            error!("could not add forwarder route to Beckhoff: {}", e);
        } else {
            info!("added forwarder route to Beckhoff successfully");
        }

        // listen for incoming connections
        let srv_sock = TcpListener::bind(("0.0.0.0", BECKHOFF_TCP_PORT))?;
        info!("TCP: bound to {}", srv_sock.local_addr()?);
        let (conn_tx, conn_rx) = channel::unbounded();

        // run distributor, it will also open connection to the BC
        self.run_tcp_distributor(conn_rx);

        // main loop: send new client sockets to distributor
        for conn in srv_sock.incoming() {
            let _ = conn_tx.send(conn?);
        }

        Ok(())
    }

    pub fn run(&mut self) -> FwdResult {
        self.run_udp("UDP-BC", BECKHOFF_BC_UDP_PORT)?;
        self.run_udp("UDP", BECKHOFF_UDP_PORT)?;
        self.run_tcp_listener()?;
        Ok(())
    }
}
