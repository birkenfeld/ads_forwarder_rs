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
use std::thread;
use byteorder::{ByteOrder, LittleEndian as LE, WriteBytesExt};
use channel::{self, Select, Receiver, Sender};
use signalbool::{Flag, Signal, SignalBool};
use mlzlog;

use Options;
use util::{hexdump, spawn, AdsMessage, AmsNetId, UdpMessage, BECKHOFF_UDP_PORT,
           BECKHOFF_BC_UDP_PORT, BECKHOFF_TCP_PORT, FWDER_NETID, DUMMY_NETID};

type FwdResult<T> = Result<T, Box<Error>>;


#[derive(Clone, PartialEq)]
pub enum BhType {
    BC,  // BC91xx
    CX2, // CX with TwinCat 2
    CX3, // CX with TwinCat 3
}

#[derive(Clone)]
pub struct Beckhoff {
    pub if_addr: Ipv4Addr,
    pub bh_addr: Ipv4Addr,
    pub netid: AmsNetId,
    pub typ: BhType,
}

impl Beckhoff {
    /// Add a route on the Beckhoff, to `netid` via our interface address.
    fn add_route(&self, netid: &AmsNetId, name: &str) -> FwdResult<()> {
        if self.typ == BhType::BC {
            // no routes necessary on BCs
            return Ok(());
        }

        let sock = UdpSocket::bind(("0.0.0.0", 0))?;
        sock.set_read_timeout(Some(Duration::from_millis(1500)))?;

        for password in &["", "1"] {
            let mut msg = UdpMessage::new(UdpMessage::ADD_ROUTE, netid, 10000);
            msg.add_str(UdpMessage::ROUTENAME, name);
            msg.add_bytes(UdpMessage::NETID, &netid.0);
            msg.add_str(UdpMessage::USERNAME, "Administrator");
            msg.add_str(UdpMessage::PASSWORD, password);
            msg.add_str(UdpMessage::HOST, &format!("{}", self.if_addr));
            if self.typ == BhType::CX3 {
                // mark as temporary route (seems to crash CXs with TC2)
                msg.add_u32(UdpMessage::OPTIONS, 1);
            }
            sock.send_to(&msg.into_bytes(), (self.bh_addr, BECKHOFF_UDP_PORT))?;

            let mut reply = [0; 2048];
            let (len, _) = sock.recv_from(&mut reply)?;
            let msg = UdpMessage::parse(&reply[..len], UdpMessage::ADD_ROUTE)?;
            match msg.get_u32(UdpMessage::STATUS) {
                Some(0) => return Ok(()),
                Some(0x0704) => continue,
                Some(e) => Err(format!("error return when adding route: {:#x}", e))?,
                None => Err(format!("invalid return message adding route"))?,
            }
        }
        Err("standard Administrator passwords not accepted".into())
    }

    /// Remove all routes on the Beckhoff with given name.
    fn remove_routes(&self, sock: &mut TcpStream, name: &str) -> FwdResult<()> {
        if self.typ == BhType::BC {
            return Ok(());
        }

        let mut data = Vec::new();
        data.write_u32::<LE>(0x322).unwrap(); // Index-group for removing routes
        data.write_u32::<LE>(0).unwrap();     // Index-offset
        data.write_u32::<LE>(name.len() as u32 + 1).unwrap(); // Data-len
        data.write_all(name.as_bytes()).unwrap();
        data.write_all(&[0]).unwrap();
        let msg = AdsMessage::new(&self.netid, 10000, &FWDER_NETID, 40001,
                                  AdsMessage::WRITE, &data);
        sock.write_all(&msg.0)?;

        Ok(())
    }
}


/// Represents the whole forwarder, which forwards TCP and UDP
/// messages between the Beckhoff and any number of clients.
pub struct Forwarder {
    opts: Options,
    bh: Beckhoff,
}

/// The distributor is the heart of the TCP part of the forwarder.
/// Its thread receives client messages and forwards them to the
/// Beckhoff, and distributes replies among the respective clients.
struct Distributor {
    bh: Beckhoff,
    ids: Vec<u8>,
    dump: bool,
    sig: SignalBool,
}

/// Represents a single client connection.
struct ClientConn {
    sock: TcpStream, // socket to write messages to
    chan: Receiver<ReadEvent>, // channel to receive messages (or quit)
    peer: SocketAddr, // peer address for convenience
    client_id: AmsNetId, // client's real ID
    clients_bh_id: AmsNetId, // client thinks this is Beckhoff's ID
    virtual_id: AmsNetId, // virtual ID for the temporary route
}

enum ReadEvent {
    Msg(AdsMessage),
    Quit,
}

fn read_loop(mut sock: TcpStream, chan: Sender<ReadEvent>) {
    loop {
        let mut message = Vec::with_capacity(100);
        // read size
        message.resize(6, 0);
        if sock.read_exact(&mut message).is_err() {
            let _ = chan.send(ReadEvent::Quit);
            return;
        }
        let size = LE::read_u32(&message[2..6]);
        // read rest of message
        message.resize(size as usize + 6, 0);
        if sock.read_exact(&mut message[6..]).is_err() {
            let _ = chan.send(ReadEvent::Quit);
            return;
        }
        // send message to distributor
        if chan.send(ReadEvent::Msg(AdsMessage::from_bytes(message))).is_err() {
            return;
        }
    }
}


impl Distributor {
    /// Connect a TCP socket to the Beckhoff, start a reader thread and return
    /// the socket and the channel to receive messages.
    fn connect(&mut self) -> FwdResult<(TcpStream, Receiver<ReadEvent>)> {
        // connect to Beckhoff
        let bh_sock = TcpStream::connect((self.bh.bh_addr, BECKHOFF_TCP_PORT))?;
        info!("connected to Beckhoff at {}", bh_sock.peer_addr()?);
        let (bh_tx, bh_rx) = channel::unbounded();

        // start keep-alive thread
        if self.bh.typ == BhType::BC {
            info!("starting BC keepalive thread");
            self.run_keepalive(&bh_sock)?;
        }

        // send BH replies from socket to distributor
        let bh_sock2 = bh_sock.try_clone()?;
        spawn("BH reader", move || read_loop(bh_sock2, bh_tx));
        Ok((bh_sock, bh_rx))
    }

    /// Since the BC boxes close a TCP connection after 10 seconds of inactivity,
    /// this thread sends an "identify" message to it every 3 seconds.
    ///
    /// To be able to catch and discard the replies in the distributor, the source
    /// NetID is set to a known dummy value.
    fn run_keepalive(&self, sock: &TcpStream) -> FwdResult<()> {
        let mut bh_sock = sock.try_clone()?;
        let msg = AdsMessage::new(&self.bh.netid, 10000, &DUMMY_NETID, 40001,
                                  AdsMessage::DEVINFO, &[]);

        spawn("keepalive", move || loop {
            mlzlog::set_thread_prefix("TCP: ".into());
            thread::sleep(Duration::from_secs(3));
            if bh_sock.write_all(&msg.0).is_err() {
                debug!("keepalive thread exiting");
                break;
            }
        });
        Ok(())
    }

    /// Main entry point for the distributor.
    ///
    /// Opens a connection and handles messages; if the Beckhoff connection
    /// is closed, it is tried to reopen every second.
    fn run(&mut self, conn_rx: Receiver<TcpStream>) {
        mlzlog::set_thread_prefix("TCP: ".into());
        while !self.sig.caught() {
            match self.connect() {
                Ok((bh_sock, bh_chan)) => self.handle(&conn_rx, bh_sock, bh_chan),
                Err(e) => {
                    error!("error on connection to Beckhoff: {}", e);
                    thread::sleep(Duration::from_secs(1));
                }
            }
        }
    }

    /// Handle messages once the connection to the Beckhoff is established.
    fn handle(&mut self, conn_rx: &Receiver<TcpStream>, mut bh_sock: TcpStream,
              bh_chan: Receiver<ReadEvent>)
    {
        let mut clients = Vec::<ClientConn>::new();
        let mut cleanup = None;
        loop {
            // select loop - always break after Ok replies!
            let mut sel = Select::with_timeout(Duration::from_millis(500));
            'select: loop {
                // cleanup clients
                if let Some(peer) = cleanup.take() {
                    clients.retain(|client| client.peer != peer);
                }
                // check for interrupt signal
                if self.sig.caught() {
                    info!("exiting, removing routes...");
                    if let Err(e) = self.bh.remove_routes(&mut bh_sock, "forwarder") {
                        warn!("could not remove forwarder route: {}", e);
                    }
                    if let Err(e) = self.bh.remove_routes(&mut bh_sock, "fwdclient") {
                        warn!("could not remove forwarder client routes: {}", e);
                    }
                    return;
                }
                // check for new connections
                if let Ok(sock) = sel.recv(&conn_rx) {
                    match self.new_tcp_conn(sock) {
                        Err(e) => warn!("error handling new client connection: {}", e),
                        Ok(client) => clients.push(client),
                    }
                    break 'select;
                }
                // check for replies from Beckhoff
                if let Ok(x) = sel.recv(&bh_chan) {
                    if let ReadEvent::Msg(mut reply) = x {
                        for client in &mut clients {
                            if client.virtual_id == reply.dest_id() {
                                self.new_beckhoff_msg(reply, client);
                                break 'select;
                            }
                        }
                        if reply.dest_id() != DUMMY_NETID {
                            // unhandled message, something went wrong...
                            warn!("message from Beckhoff to {} not forwarded", reply.dest_id());
                        }
                    } else {
                        error!("Beckhoff closed socket!");
                        // note: this will close all client connections
                        // and clients have to reconnect
                        return;
                    }
                    break 'select;
                }
                // check for requests from clients
                for mut client in &mut clients {
                    if let Ok(x) = sel.recv(&client.chan) {
                        if let ReadEvent::Msg(mut request) = x {
                            self.new_client_msg(request, &mut client, &mut bh_sock);
                        } else {
                            // client socket closed -- remove it on next iteration
                            info!("connection from {} closed", client.peer);
                            let cid = client.virtual_id.0[3];
                            if cid != 0 {
                                self.ids.push(cid);
                            }
                            cleanup = Some(client.peer);
                        }
                        break 'select;
                    }
                }
            }
        }
    }

    /// Handles a new incoming TCP connection.
    ///
    /// Starts a thread to read messages from the connection, and sets up
    /// a channel to receive them.  Also assigns a virtual NetID to to use
    /// for the back-route from the Beckhoff.
    fn new_tcp_conn(&mut self, sock: TcpStream) -> FwdResult<ClientConn> {
        let peer = sock.peer_addr()?;
        info!("new connection from {}", peer);
        let (cl_tx, cl_rx) = channel::unbounded();
        let sock2 = sock.try_clone()?;
        spawn("client reader", move || read_loop(sock2, cl_tx));
        let id = self.ids.pop().ok_or("too many clients")?;
        let virtual_id = AmsNetId([10, 1, 0, id, 1, 1]);
        info!("assigned virtual NetID {}", virtual_id);
        Ok(ClientConn { sock, peer, virtual_id, chan: cl_rx,
                        client_id: Default::default(),
                        clients_bh_id: Default::default() })
    }

    /// Handles a message coming from the Beckhoff intended for the given client.
    fn new_beckhoff_msg(&mut self, mut reply: AdsMessage, client: &mut ClientConn) {
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
    }

    /// Handles a message coming from the given client.
    fn new_client_msg(&self, mut request: AdsMessage, client: &mut ClientConn, bh_sock: &mut TcpStream) {
        // first request: remember NetIDs of the requests
        if client.client_id.is_zero() {
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


impl Forwarder {
    pub fn new(opts: Options, bh: Beckhoff) -> Self {
        Forwarder { opts, bh }
    }

    /// Run the UDP forwarder on a given UDP port.
    ///
    /// Since the BC and CX models use different UDP ports and protocols,
    /// we start two of these.
    fn run_udp(&self, name: &'static str, port: u16) -> FwdResult<()> {
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

    /// Run the TCP distributor, receiving new client connections on the given channel.
    fn run_tcp_distributor(&mut self, conn_rx: Receiver<TcpStream>) {
        let mut distributor = Distributor {
            bh: self.bh.clone(),
            ids: (1..255).rev().collect(),
            dump: self.opts.verbosity >= 2,
            sig: SignalBool::new(&[Signal::SIGINT],
                                 Flag::Restart).unwrap(),
        };

        distributor.run(conn_rx);
    }

    /// Run the TCP listener, sending new client connections to the given channel.
    fn run_tcp_listener(&mut self, conn_tx: Sender<TcpStream>) -> FwdResult<()> {
        // listen for incoming connections
        let srv_sock = TcpListener::bind(("0.0.0.0", BECKHOFF_TCP_PORT))?;
        info!("TCP: bound to {}", srv_sock.local_addr()?);

        spawn("listener", move || {
            // main loop: send new client sockets to distributor
            for conn in srv_sock.incoming() {
                if let Ok(conn) = conn {
                    let _ = conn_tx.send(conn);
                }
            }
        });
        Ok(())
    }

    /// Run the whole forwarder.
    pub fn run(&mut self) -> FwdResult<()> {
        // start UDP forwarding
        self.run_udp("UDP-BC", BECKHOFF_BC_UDP_PORT)?;
        self.run_udp("UDP", BECKHOFF_UDP_PORT)?;
        if self.opts.udponly {
            loop {
                // threads are doing all the work
                thread::sleep(Duration::from_secs(1));
            }
        } else {
            // add route to ourselves - without it, TCP connections are
            // closed immediately
            if let Err(e) = self.bh.add_route(&FWDER_NETID, "forwarder") {
                Err(format!("TCP: while adding backroute: {}", e))?;
            } else {
                info!("TCP: added backroute to forwarder");
            }
            // start TCP forwarding
            let (conn_tx, conn_rx) = channel::unbounded();
            self.run_tcp_listener(conn_tx)?;
            self.run_tcp_distributor(conn_rx);
        }
        Ok(())
    }
}
