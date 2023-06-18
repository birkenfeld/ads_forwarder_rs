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

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, UdpSocket, SocketAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use std::thread;

use ads::{AmsAddr, AmsNetId, udp};
use anyhow::{anyhow, bail, Context, Result};
use log::{debug, info, warn, error};
use byteorder::{ByteOrder, LittleEndian as LE, WriteBytesExt};
use crossbeam_channel::{self, Receiver, Sender, Select};
use mlzutil::{spawn, bytes::hexdump};

use crate::Options;
use crate::util::{AdsMessage, InOutClientBH, BECKHOFF_UDP_PORT, BECKHOFF_BC_UDP_PORT,
                  BECKHOFF_TCP_PORT, DUMMY_NETID, FWDER_NETID, GETSTATE, ADDNOTIF,
                  DELNOTIF, NOTIF, WRITE, DEVINFO, NotifData};


#[derive(Clone, PartialEq, Eq)]
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
    fn add_route(&self, netid: AmsNetId, name: &str) -> Result<()> {
        if self.typ == BhType::BC {
            // no routes necessary on BCs
            return Ok(());
        }
        let sock = UdpSocket::bind(("0.0.0.0", 0)).context("binding UDP socket")?;
        sock.set_read_timeout(Some(Duration::from_millis(1500)))?;

        for password in &["", "1"] {
            let mut msg = udp::Message::new(udp::ServiceId::AddRoute, AmsAddr::new(netid, 10000));
            msg.add_str(udp::Tag::RouteName, name);
            msg.add_bytes(udp::Tag::NetID, &netid.0);
            msg.add_str(udp::Tag::UserName, "Administrator");
            msg.add_str(udp::Tag::Password, password);
            msg.add_str(udp::Tag::ComputerName, &format!("{}", self.if_addr));
            sock.send_to(msg.as_bytes(), (self.bh_addr, BECKHOFF_UDP_PORT))?;

            let mut reply = [0; 2048];
            let (len, _) = sock.recv_from(&mut reply).context("getting route reply")?;
            let msg = udp::Message::parse(&reply[..len], udp::ServiceId::AddRoute, true)
                .context("parsing route reply")?;
            match msg.get_u32(udp::Tag::Status) {
                Some(0) => { info!("added route if_addr={} netid={netid}", self.bh_addr);
                             return Ok(())},
                Some(0x0704) => continue,  // password not accepted
                Some(err) => bail!("error return when adding route: {err:#x}"),
                None => bail!("invalid return message adding route"),
            }
        }
        bail!("standard Administrator passwords not accepted");
    }

    /// Remove all routes on the Beckhoff with given name.
    fn remove_routes(&self, sock: &mut TcpStream, netid: &AmsNetId,
                     name: &str) -> Result<()> {
        if self.typ == BhType::BC {
            return Ok(());
        }
        let mut data = Vec::new();
        data.write_u32::<LE>(0x322).unwrap(); // Index-group for removing routes
        data.write_u32::<LE>(0).unwrap();     // Index-offset
        data.write_u32::<LE>(name.len() as u32 + 1).unwrap(); // Data-len
        data.write_all(name.as_bytes()).unwrap();
        data.write_all(&[0]).unwrap();
        let invoke_id = 0;

        let msg = AdsMessage::new(self.netid, 10000, *netid, 40001,
                                  WRITE, false, invoke_id, &data);
        sock.write_all(&msg.0).context("removing routes")?;

        Ok(())
    }
}


/// Represents the whole forwarder, which forwards TCP and UDP
/// messages between the Beckhoff and any number of clients.
pub struct Forwarder {
    opts: Options,
    bh: Beckhoff,
}

struct ClientRequest {
    index: usize,
    invoke_id: u32,
    add_notif_req_data: Option::<crate::util::AddNotifReqData>,
}

/// The distributor is the heart of the TCP part of the forwarder.
/// Its thread receives client messages and forwards them to the
/// Beckhoff, and distributes replies among the respective clients.
struct Distributor {
    bh: Beckhoff,
    local_ams_net_id: AmsNetId,
    ids: Vec<u8>,
    dump: bool,
    summarize: bool,
    single_ams_net_id: bool,
    sig: Arc<AtomicBool>,
    clients: Vec<ClientConn>,
    invoke_id_client_req: u32,
    invoke_id_our_req: u32,
    /* As we patch the invoke ID before sending it to the Beckhoff with
       our own maintained invoke ID, we need to remember which client
       belongs to which invoke ID */
    invoke_id_to_client_map: HashMap<u32, ClientRequest>,
    /*
       Notifications: When different (or the same) clients asks for notifications,
       they are "shared", kind of. We only ask for one notification towards the PLC
       To find shared notifications, store it in notif_req_data_to_handle_map
       When notifications come from the PLC, notifications are distributed
       to the different clients.
     */
    notif_req_data_to_handle_map: HashMap<crate::util::AddNotifReqData, u32>,
    notif_handle_to_client_indices_map: HashMap<u32, Vec<usize>>,
    notif_handle_to_last_notif_stream_map: HashMap<u32, NotifData>,
    //notification_req_client_map: HashMap<u32, crate::util::AddNotifReqData>,
    conn_rx: Receiver<TcpStream>,
    bh_tx: Sender<ReadEvent>,
}

/// Represents a single client connection.
struct ClientConn {
    used: bool,      // Used (or closed and ready for re-use at some time)
    sock: TcpStream, // socket to write messages to
    chan: Receiver<ReadEvent>, // channel to receive messages (or quit)
    peer: SocketAddr, // peer address for convenience
    client_id: AmsNetId, // client's real ID
    client_source_port: u16,
    clients_bh_id: AmsNetId, // client thinks this is Beckhoff's ID
    clients_bh_dest_port: u16, // client talks to this port
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

enum DistEvent {
    None,
    BeckhoffMessage(AdsMessage),
    BeckhoffQuit,
    ClientMessage(usize, AdsMessage),
    ClientQuit(usize),
    NewClient(TcpStream),
}

impl Distributor {
    /// Connect a TCP socket to the Beckhoff, start a reader thread and return
    /// the socket and the channel to receive messages.
    fn connect(&mut self) -> Result<(TcpStream, Receiver<ReadEvent>)> {
        // connect to Beckhoff
        let bh_sock = TcpStream::connect((self.bh.bh_addr, BECKHOFF_TCP_PORT))
            .context("connecting to Beckhoff")?;
        bh_sock.set_nodelay(true)?;
        info!("connected to Beckhoff at {}", bh_sock.peer_addr()?);
        let (bh_tx, bh_rx) = crossbeam_channel::unbounded();

        // start keep-alive thread
        if self.bh.typ == BhType::BC {
            info!("starting BC keepalive thread");
            self.run_keepalive(&bh_sock)?;
        }

        // send BH replies from socket to distributor
        let bh_sock2 = bh_sock.try_clone()?;
        let bh_tx2 = bh_tx.clone();
        spawn("BH reader", move || read_loop(bh_sock2, bh_tx2));
        self.bh_tx = bh_tx;
        Ok((bh_sock, bh_rx))
    }

    /// Since the BC boxes close a TCP connection after 10 seconds of inactivity,
    /// this thread sends an "identify" message to it every 3 seconds.
    ///
    /// To be able to catch and discard the replies in the distributor, the source
    /// NetID is set to a known dummy value.
    fn run_keepalive(&self, sock: &TcpStream) -> Result<()> {
        let mut bh_sock = sock.try_clone()?;
        let invoke_id = 0;
        let msg = AdsMessage::new(self.bh.netid, 10000, DUMMY_NETID, 40001,
                                  DEVINFO, false, invoke_id, &[]);

        spawn("keepalive", move || loop {
            mlzlog::set_thread_prefix("TCP: ");
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
    fn run(mut self) {
        mlzlog::set_thread_prefix("TCP: ");
        while !self.sig.load(Ordering::Relaxed) {
            self.clients.clear();
            match self.connect() {
                Ok((bh_sock, bh_chan)) => self.handle_msg(bh_sock, bh_chan), // XX3
                Err(err) => {
                    error!("error on connection to Beckhoff: {err:#}");
                    thread::sleep(Duration::from_secs(1));
                }
            }
        }
    }

    /// Wait for an event from all possible sources.
    fn get_event(&self, bh_chan: &Receiver<ReadEvent>) -> DistEvent {
        let mut select = Select::new();
        let clients_len = 1 + self.clients.len();
        let mut index_in_clients: Vec<usize> = Vec::with_capacity(clients_len);
        // Thindex in clients may be 0,1,2,3
        // When client[2] is disconnected and not used,
        // the index in select would be 0,1,3
        for index in 0..clients_len - 1 {
            if self.clients[index].used {
                select.recv(&self.clients[index].chan);
                index_in_clients.push(index);
            }
        }
        let new_conn = select.recv(&self.conn_rx);
        select.recv(bh_chan);
        let event = select.select_timeout(Duration::from_millis(500));
        if let Ok(event) = event {
            let index = event.index();
            if index == new_conn {
                DistEvent::NewClient(event.recv(&self.conn_rx).unwrap())
            } else if index < new_conn {
                let index = index_in_clients[event.index()];
                if let Ok(ReadEvent::Msg(msg)) = event.recv(&self.clients[index].chan) { // XX1
                    DistEvent::ClientMessage(index, msg)
                } else {
                    DistEvent::ClientQuit(index)
                }
            } else if let Ok(ReadEvent::Msg(msg)) = event.recv(bh_chan) {
                DistEvent::BeckhoffMessage(msg)
            } else {
                DistEvent::BeckhoffQuit
            }
        } else {
            DistEvent::None
        }
    }

    /// Handle a notification message by splitting it into individual messages for
    /// possibly different clients
    fn handle_notification(&mut self, msg: AdsMessage) {
        if let Ok(notif) = ads::notif::Notification::new(msg.0) {
            for sample in notif.samples() {
                match self.notif_handle_to_client_indices_map.get(&sample.handle) {
                    Some(notif_indices) => {
                        let mut any_client = false;
                        let is_reply = false;
                        let invoke_id = 0;
                        // Construct a fake message with a single notification
                        let mut notif_data = NotifData::new();
                        notif_data.add_stamp(sample.timestamp, &[(sample.handle, sample.data)]);
                        for &index in notif_indices {
                            if self.clients.len() > index {
                                let client = &self.clients[index];
                                if client.used {
                                    let reply = AdsMessage::new(client.client_id,
                                                                client.client_source_port,
                                                                client.clients_bh_id,
                                                                client.clients_bh_dest_port,
                                                                NOTIF,
                                                                is_reply,
                                                                invoke_id,
                                                                notif_data.data());
                                    if self.summarize {
                                        reply.summarize(InOutClientBH::OutToClnt, self.dump);
                                    }
                                    if let Err(err) = (&client.sock).write_all(&reply.0) {
                                        warn!("error forwarding reply to client: {err}");
                                    }
                                    any_client = true;
                                }
                            } else {
                                info!("TODO: get_event client not in list any more index={index}");
                            }
                        }
                        if any_client {
                            self.notif_handle_to_last_notif_stream_map.insert(sample.handle, notif_data);
                        } else {
                            // It may happen, that we have send a DELNOTIF
                            // and there are a few notifications in the pipe.
                            // If we have old notif_data for this handle, something is wrong
                            match self.notif_handle_to_last_notif_stream_map.remove(&sample.handle) {
                                Some(_notif_data) => {
                                    info!("get_event no client any more sample.handle={}",
                                          sample.handle);
                                }
                                None => {}
                            }
                        }
                    }
                    None => info!("get_event notif_handle_to_client_indices_map.get=None sample.handle={}",
                                  sample.handle)
                }
            }
        }
    }

    /// Handle messages once the connection to the Beckhoff is established.
    fn handle_msg(&mut self, mut bh_sock: TcpStream, bh_chan: Receiver<ReadEvent>) {
        'select: loop {
            // check for interrupt signal
            if self.sig.load(Ordering::Relaxed) {
                info!("exiting, removing routes...");
                if let Err(err) = self.bh.remove_routes(&mut bh_sock, &self.local_ams_net_id, "forwarder") {
                    warn!("could not remove forwarder route: {err:#}");
                }
                if let Err(err) = self.bh.remove_routes(&mut bh_sock, &self.local_ams_net_id, "fwdclient") {
                    warn!("could not remove forwarder client routes: {err:#}");
                }
                return;
            }
            // get an event
            match self.get_event(&bh_chan) {
                DistEvent::NewClient(sock) => if let Err(err) = self.new_tcp_conn(sock) {
                    warn!("error handling new client connection: {err:#}");
                },
                DistEvent::ClientMessage(index, msg) => {
                    self.client_msg(msg, index, &mut bh_sock);
                },
                DistEvent::BeckhoffMessage(mut msg) => {
                    if self.summarize {
                        info!("From Beckhoff =========================================");
                        msg.summarize(InOutClientBH::InFrmBeck, self.dump);
                    }

                    // Reply to GetState query from the Beckhoff's AMS router
                    if msg.get_dest_id() == self.local_ams_net_id && msg.get_cmd() == GETSTATE {
                        let stf = msg.get_state_flags();
                        let is_reply = stf & 1 != 0;
                        if !is_reply {
                            let reply_msg = AdsMessage::new(self.bh.netid, 10000,
                                                            self.local_ams_net_id, 10000, 4,
                                                            true, 0, b"\x00\x05\x00\x00");
                            bh_sock.write_all(&reply_msg.0).unwrap();
                            info!("replied to router GetState msg");
                            continue 'select;
                        }
                    }

                    if self.single_ams_net_id {
                        let cmd = msg.get_cmd();
                        if cmd == DELNOTIF {
                            // Do something ?
                            continue 'select;
                        } else if cmd == NOTIF {
                            self.handle_notification(msg);
                            continue 'select;
                        }

                        // find the matching invoke ID and client for this message
                        let invoke_id_patched = msg.get_invoke_id();
                        match self.invoke_id_to_client_map.remove(&invoke_id_patched) {
                            Some(client_req) => {
                                let index = client_req.index;
                                let invoke_id_orig = client_req.invoke_id;
                                msg.patch_invoke_id(invoke_id_orig);

                                // if it is an add-notification message, remember the notification handles
                                if let Some(handle) = msg.get_add_notification_reply_handle() {
                                    debug!("get_event notif cmd={cmd} handle={handle}");
                                    match client_req.add_notif_req_data {
                                        Some(add_notif_req_data) => {
                                            self.notif_req_data_to_handle_map.insert(add_notif_req_data, handle);
                                            match self.notif_handle_to_client_indices_map.get_mut(&handle) {
                                                Some(notif_indices) => {
                                                    debug!("get_event notif notif_indices=\
                                                            {notif_indices:?} index={index}");
                                                    notif_indices.push(index);
                                                }
                                                _ => {
                                                    let mut notif_indices = Vec::new();
                                                    debug!("get_event notif notif_indices=new index={index}");
                                                    notif_indices.push(index);
                                                    self.notif_handle_to_client_indices_map.insert(
                                                        handle, notif_indices);
                                                }
                                            }
                                        },
                                        _ => {
                                            info!("get_add_notification_reply_handle=None");
                                        }
                                    }
                                }
                                let index = client_req.index;
                                if index >= self.clients.len() {
                                    info!("get_event index={index} has gone clients.len()={}",
                                          self.clients.len());
                                    // TODO: We lose a handle here on the PLC
                                    continue 'select;
                                }

                                let client = &self.clients[index];
                                if client.used {
                                    self.msg_from_beckhoff(msg, client);
                                }
                                continue 'select;
                            },
                            None => {
                                info!("get_event invoke_id_patched={invoke_id_patched} NOT FOUND");
                            },
                        }
                        continue 'select;
                    }
                    for client in &self.clients {
                        if client.used && client.virtual_id == msg.get_dest_id() {
                            self.msg_from_beckhoff(msg, client);
                            continue 'select;
                        }
                    }
                    if msg.get_dest_id() == DUMMY_NETID {
                        // keepalive reply
                        continue;
                    }
                    if msg.get_dest_id() != self.local_ams_net_id {
                        warn!("message from Beckhoff to {} not forwarded", msg.get_dest_id());
                        continue 'select;
                    }
                    if msg.get_cmd() == GETSTATE {
                        let reply_msg = AdsMessage::new(self.bh.netid, 10000, self.local_ams_net_id,
                                                        10000, 4, true, 0, b"\x00\x05\x00\x00");
                        bh_sock.write_all(&reply_msg.0).unwrap();
                        info!("replied to router GetState msg");
                    }
                },
                DistEvent::ClientQuit(index) => {
                    if self.single_ams_net_id {
                        let clientx = &mut self.clients[index];
                        clientx.used = false;
                        info!("connection from {} closed", clientx.peer);
                    } else {
                        let clientx = self.clients.swap_remove(index);
                        let cid = clientx.virtual_id.0[3];
                        if cid != 0 {
                            self.ids.push(cid);
                        }
                        info!("connection from {} closed", clientx.peer);
                    }
                    let mut notif_req_data_to_beleted = Vec::new();
                    for notif_req_data in self.notif_req_data_to_handle_map.keys() {
                        debug!("ClientQuit notif_req_data_to_handle_map notif_req_data={notif_req_data:?}");
                        if let Some(&handle) = self.notif_req_data_to_handle_map.get(notif_req_data) {
                            match self.notif_handle_to_client_indices_map.get_mut(&handle) {
                                Some(notif_indices) => {
                                    debug!("ClientQuit handle={handle} notif_indices={notif_indices:?}");
                                    let mut nindex = 0;
                                    let mut removed_index = 0xFFFFFFF;
                                    while nindex < notif_indices.len() {
                                        if notif_indices[nindex] == index {
                                            removed_index = notif_indices.swap_remove(nindex);
                                            break;
                                        }
                                        nindex += 1;
                                    }
                                    if notif_indices.is_empty() {
                                        //notif_req_data_to_beleted.push(Some(*notif_req_data));
                                        notif_req_data_to_beleted.push(*notif_req_data);
                                        debug!("ClientQuit notif_handle_to_client_indices_map notif_indices \
                                                after=empty removed_index={removed_index}");
                                        let is_reply = false;
                                        self.invoke_id_our_req = (self.invoke_id_our_req + 1) & 0xFFFF;
                                        let invoke_id = self.invoke_id_our_req;
                                        let mut data = Vec::new();
                                        data.write_u32::<LE>(handle).unwrap();

                                        let req_msg = AdsMessage::new(self.bh.netid,
                                                                      notif_req_data.dest_port,
                                                                      self.local_ams_net_id,
                                                                      10000,
                                                                      DELNOTIF, is_reply, invoke_id,
                                                                      &data);
                                        if self.summarize {
                                            info!("To Beckhoff =========================================");
                                            req_msg.summarize(InOutClientBH::OutToBeck, self.dump);
                                        }
                                        bh_sock.write_all(&req_msg.0).unwrap();
                                        self.notif_handle_to_last_notif_stream_map.remove(&handle);

                                    } else {
                                        debug!("ClientQuit notif_handle_to_client_indices_map \
                                                notif_indices after={notif_indices:?} removed_index={removed_index}");
                                    }
                                    debug!("ClientQuit after retain: notif_indices={notif_indices:?}");
                                }
                                None => debug!("ClientQuit notif_indices=None"),
                            }
                        }
                    }
                    // Delete the handle from the map
                    debug!("ClientQuit notif_req_data_to_beleted={notif_req_data_to_beleted:?}");
                    for notif_req_data in notif_req_data_to_beleted {
                        let handle = self.notif_req_data_to_handle_map.remove(&notif_req_data);
                        debug!("ClientQuit notif_req_data_to_handle_map.remove \
                                notif_req_data={notif_req_data:?} handle={handle:?}");
                    }
                },
                DistEvent::BeckhoffQuit => {
                    error!("Beckhoff closed socket!");
                    for client in &mut self.clients {
                        if client.used {
                            if let Err(err) = client.sock.shutdown(Shutdown::Both) {
                                warn!("error shutting down client: {err}");
                            }
                        }
                    }
                    self.notif_req_data_to_handle_map.clear();
                    self.notif_handle_to_client_indices_map.clear();
                    self.notif_handle_to_last_notif_stream_map.clear();
                    return;
                },
                DistEvent::None => continue
            }
        }
    }

    /// Handles a new incoming TCP connection.
    ///
    /// Starts a thread to read messages from the connection, and sets up
    /// a channel to receive them.  Also assigns a virtual NetID to to use
    /// for the back-route from the Beckhoff.
    fn new_tcp_conn(&mut self, sock: TcpStream) -> Result<()> {
        let peer = sock.peer_addr()?;
        if peer.ip() == self.bh.bh_addr {
            info!("new back-connection from Beckhoff");
            let bh_tx = self.bh_tx.clone();
            spawn("BH reader", move || read_loop(sock, bh_tx));
            return Ok(())
        }
        info!("new connection from {peer}");
        let (cl_tx, cl_rx) = crossbeam_channel::unbounded();
        let sock2 = sock.try_clone()?;
        spawn("client reader", move || read_loop(sock2, cl_tx));
        let id = self.ids.pop().ok_or_else(|| anyhow!("too many clients"))?;
        let virtual_id = AmsNetId([10, 1, 0, id, 1, 1]);
        if ! self.single_ams_net_id {
            info!("assigned virtual NetID {virtual_id}");
        }
        self.clients.push(ClientConn { used: true, sock, peer, virtual_id, chan: cl_rx,
                                       client_id: Default::default(),
                                       client_source_port: 0,
                                       clients_bh_id: Default::default(),
                                       clients_bh_dest_port: 0});
        Ok(())
    }

    /// Handles a message coming from the Beckhoff intended for the given client.
    fn msg_from_beckhoff(&self, mut reply: AdsMessage, client: &ClientConn) {
        reply.patch_source_id(client.clients_bh_id);
        reply.patch_dest_id(client.client_id);
        reply.patch_dest_port(client.client_source_port);
         if self.summarize {
             reply.summarize(InOutClientBH::OutToClnt, self.dump);
         }
        if reply.0.len() == 0xae && reply.0[0x6e..0x74] == client.virtual_id.0 {
            info!("mangling NetID in 'login' query");
            reply.0[0x6e..0x74].copy_from_slice(&client.client_id.0);
        }
        // if the socket is closed, the next read attempt will return Quit
        // and the client will be dropped, so only log send failures here
        if let Err(err) = (&client.sock).write_all(&reply.0) {
            warn!("error forwarding reply to client: {err}");
        }
    }

    /// Handles a message coming from the given client.
    fn client_msg(&mut self, mut request: AdsMessage, index: usize, bh_sock: &mut TcpStream) {
        if self.summarize {
            info!("From Client =========================================");
            request.summarize(InOutClientBH::InFrmClnt, self.dump);
        }
        // first request: remember NetIDs of the requests
        let client = &mut self.clients[index];
        if client.client_id.is_zero() {
            info!("client {} has NetID {}", client.peer, request.get_source_id());
            client.client_id = request.get_source_id();
            client.client_source_port = request.get_source_port();
            client.clients_bh_id = request.get_dest_id();
            client.clients_bh_dest_port = request.get_dest_port();

            if !self.single_ams_net_id {
                if let Err(err) = self.bh.add_route(client.virtual_id, "fwdclient") {
                    error!("error setting up client route: {err}");
                } else {
                    info!("added client route successfully");
                }
            }
        }
        if self.bh.typ == BhType::BC {
            request.patch_dest_id(self.bh.netid);
        }
        if self.single_ams_net_id {
            /* Notifications are special: if there are 2 of the same kind.
               we just send 1 to the PLC, and distribute
               the notifications to all clients, that asked for it.
            */
            let mut add_notif_req_data = None;
            if request.get_cmd() == ADDNOTIF {
                add_notif_req_data = request.get_add_notif_req_data();
                debug!("client_msg add_notif_req_data={add_notif_req_data:#?}");

                /************************************/
                if let Some(add_notif_req_data0) = add_notif_req_data {
                    match self.notif_req_data_to_handle_map.get(&add_notif_req_data0) {
                        Some(handle) => {
                            debug!("notif_req_data_to_handle_map add_notif_req_data0=\
                                    {add_notif_req_data0:?} handle={handle}");
                            // There is already a notification
                            match self.notif_handle_to_client_indices_map.get_mut(handle) {
                                Some(notif_indices) => {
                                    debug!("get_event client_msg add_notif_req \
                                            index={index} notif_indices={notif_indices:?}");
                                    notif_indices.push(index);
                                }
                                None => {
                                    debug!("get_event add_notif_req notif_indices=None");
                                }
                            }
                            {
                                // Format a response
                                let mut data = Vec::new();
                                let result = 0;
                                data.write_u32::<LE>(result).unwrap();
                                data.write_u32::<LE>(*handle).unwrap();
                                let is_reply = true;
                                let reply_msg = AdsMessage::new(request.get_source_id(),
                                                                request.get_source_port(),
                                                                request.get_dest_id(),
                                                                request.get_dest_port(),
                                                                request.get_cmd(),
                                                                is_reply,
                                                                request.get_invoke_id(),
                                                                &data,
                                );
                                if self.summarize {
                                    request.summarize(InOutClientBH::OutToClnt, self.dump);
                                }
                                debug!("notif_req_data_to_handle_map return index={index}");
                                if let Err(err) = (&client.sock).write_all(&reply_msg.0) {
                                    warn!("error forwarding reply to client: {err}");
                                }
                            }
                            // Fake a notification
                            match self.notif_handle_to_last_notif_stream_map.get(handle) {
                                Some(notif_data) => {
                                    info!("get_event notif_handle_to_last_notif_stream_map handle={handle}");
                                    /***************/
                                    let is_reply = false;
                                    let invoke_id = 0;
                                    let noti_msg = AdsMessage::new(request.get_source_id(),
                                                                   request.get_source_port(),
                                                                   request.get_dest_id(),
                                                                   request.get_dest_port(),
                                                                   8,
                                                                   is_reply,
                                                                   invoke_id,
                                                                   notif_data.data());
                                    if self.summarize {
                                        request.summarize(InOutClientBH::OutToClnt, self.dump);
                                    }
                                    if let Err(err) = (&client.sock).write_all(&noti_msg.0) {
                                        warn!("error forwarding reply to client: {err}");
                                    }
                                    /***************/
                                }
                                None => {
                                    info!("get_event notif_handle_to_last_notif_stream_map \
                                           handle={handle} stream=None");
                                }
                            }

                            return
                        }
                        None => {
                            debug!("notif_req_data_to_handle_map \
                                    add_notif_req_data0={add_notif_req_data0:?} no handle yet");
                            request.patch_source_port(10000);
                        }
                    }
                }
            } else if request.get_cmd() == DELNOTIF {
                // Delete notification
                let mut answer_client_do_not_talk_to_beckhoff = true;
                let len = request.get_length();
                let handle = LE::read_u32(&request.0[38..]);
                info!("get_event cmd=DELNOTIF len={len} handle={handle}");
                match self.notif_handle_to_client_indices_map.get_mut(&handle) {
                    Some(notif_indices) => {
                        let mut nindex = 0;
                        let mut removed_index = 0xFFFFFFF;
                        info!("get_event cmd=DELNOTIF notif_handle_to_client_indices_map \
                               notif_indices before={notif_indices:?}");
                        // Find the client index.
                        // Note: A "client" can have more than one notifications
                        // This happens when we use a Windows system as a client,
                        // And now the windows clients are mapped into one client against us
                        while nindex < notif_indices.len() {
                            if notif_indices[nindex] == index {
                                removed_index = notif_indices.swap_remove(nindex);
                                break;
                            }
                            nindex += 1;
                        }
                        if notif_indices.is_empty() {
                            info!("get_event cmd=DELNOTIF notif_handle_to_client_indices_map \
                                   notif_indices after=empty removed_index={removed_index}");
                            if removed_index == index {
                                answer_client_do_not_talk_to_beckhoff = false;
                            }
                        } else {
                            info!("get_event cmd=DELNOTIF notif_handle_to_client_indices_map \
                                   notif_indices after={notif_indices:?} \
                                   removed_index={removed_index}");
                        }
                    }
                    None => {
                        info!("get_event cmd=DELNOTIF notif_handle_to_client_indices_map.get=None");
                    }
                }
                if answer_client_do_not_talk_to_beckhoff {
                    let is_reply = true;
                    let reply_msg = AdsMessage::new(request.get_source_id(),
                                                    request.get_source_port(),
                                                    request.get_dest_id(),
                                                    request.get_dest_port(),
                                                    request.get_cmd(),
                                                    is_reply,
                                                    request.get_invoke_id(),
                                                    b"\x00\x00\x00\x00");
                    if self.summarize {
                        reply_msg.summarize(InOutClientBH::OutToClnt, self.dump);
                    }
                    if let Err(err) = (&client.sock).write_all(&reply_msg.0) {
                        warn!("error reply cmd=DELNOTIF to client: {err}");
                    }
                    return;
                }
                // Continue: Remove the notification in Beckhoff
            }
            request.patch_source_id(self.local_ams_net_id);
            request.patch_dest_id(self.bh.netid);
            let invoke_id_orig = request.get_invoke_id();
            /* Since we do not clean up the hash table, limit the invoke id
               into a range of 64K */
            self.invoke_id_client_req = ((self.invoke_id_client_req + 1) & 0xFFFF) | 0x80000000;
            let invoke_id = self.invoke_id_client_req;
            request.patch_invoke_id(invoke_id);

            let client_req_invoke_id = ClientRequest { index,
                                                       invoke_id: invoke_id_orig,
                                                       add_notif_req_data };
            self.invoke_id_to_client_map.insert(invoke_id, client_req_invoke_id);
        } else {
            request.patch_source_id(client.virtual_id);
        }
        if self.summarize {
            request.summarize(InOutClientBH::OutToBeck, self.dump);
        }
        // if the socket is closed, the next read attempt will return Quit
        // and the connection will be reopened
        if let Err(err) = bh_sock.write_all(&request.0) {
            warn!("error forwarding request to Beckhoff: {err}");
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
    fn run_udp(&self, name: &'static str, port: u16) -> Result<()> {
        let sock = UdpSocket::bind(("0.0.0.0", port)).context("binding UDP socket")?;
        sock.set_broadcast(true)?;
        info!("{name}: bound to {}", sock.local_addr()?);

        let bh_ip = self.bh.bh_addr;
        let dump = self.opts.dump;
        spawn(name, move || {
            mlzlog::set_thread_prefix(format!("{name}: "));
            let mut active_client = ("0.0.0.0".parse().unwrap(), 0);
            let mut buf = [0; 3072];
            loop {
                if let Ok((len, addr)) = sock.recv_from(&mut buf) {
                    if addr.ip() != bh_ip {
                        let client = (addr.ip(), addr.port());
                        if client != active_client {
                            info!("active client is now {addr}");
                            active_client = client;
                        }
                        info!("{len} bytes client -> Beckhoff");
                        if dump {
                            hexdump(&buf[..len]);
                        }
                        if let Err(err) = sock.send_to(&buf[..len], (bh_ip, port)) {
                            warn!("error forwarding request to Beckhoff: {err}");
                        }
                    } else {
                        info!("{len} bytes Beckhoff -> client");
                        if dump {
                            hexdump(&buf[..len]);
                        }
                        if let Err(err) = sock.send_to(&buf[..len], active_client) {
                            warn!("error forwarding request to client: {err}");
                        }
                    }
                }
            }
        });
        Ok(())
    }

    /// Run the TCP distributor, receiving new client connections on the given channel.
    fn run_tcp_distributor(&mut self, conn_rx: Receiver<TcpStream>) {
        let atomic = Arc::new(AtomicBool::new(false));
        signal_hook::flag::register(signal_hook::consts::SIGINT, atomic.clone())
            .expect("register signal");
        signal_hook::flag::register(signal_hook::consts::SIGTERM, atomic.clone())
            .expect("register signal");

        debug!("run_tcp_distributor local_ams_net_id={:?}", self.opts.local_ams_net_id);
        Distributor {
            bh: self.bh.clone(),
            ids: (1..255).rev().collect(),
            dump: self.opts.dump,
            summarize: self.opts.summarize,
            single_ams_net_id: self.opts.single_ams_net_id,
            local_ams_net_id: self.opts.local_ams_net_id.unwrap_or(FWDER_NETID),
            sig: atomic,
            clients: Vec::with_capacity(4),
            invoke_id_client_req: 0,
            invoke_id_our_req: 0,
            invoke_id_to_client_map: HashMap::new(),
            notif_req_data_to_handle_map: HashMap::new(),
            notif_handle_to_client_indices_map: HashMap::new(),
            notif_handle_to_last_notif_stream_map: HashMap::new(),
            conn_rx,
            bh_tx: crossbeam_channel::unbounded().0,
        }.run();
    }

    /// Run the TCP listener, sending new client connections to the given channel.
    fn run_tcp_listener(&mut self, conn_tx: Sender<TcpStream>) -> Result<()> {
        // listen for incoming connections
        let srv_sock = TcpListener::bind(("0.0.0.0", BECKHOFF_TCP_PORT))
            .context("binding TCP socket")?;
        info!("TCP: bound to {}", srv_sock.local_addr()?);

        spawn("listener", move || {
            // main loop: send new client sockets to distributor
            for conn in srv_sock.incoming().flatten() {
                if conn.set_nodelay(true).is_ok() {
                    let _ = conn_tx.send(conn);
                }
            }
        });
        Ok(())
    }

    /// Run the whole forwarder.
    pub fn run(&mut self) -> Result<()> {
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
            if let Err(err) = self.bh.add_route(
                self.opts.local_ams_net_id.unwrap_or(FWDER_NETID), "forwarder")
            {
                bail!("TCP: while adding backroute: {err}");
            }
            // start TCP forwarding
            let (conn_tx, conn_rx) = crossbeam_channel::unbounded();
            self.run_tcp_listener(conn_tx)?;
            self.run_tcp_distributor(conn_rx);
        }
        Ok(())
    }
}
