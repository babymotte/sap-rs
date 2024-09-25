/*
 *  Copyright (C) 2024 Michael Bachmann
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

use error::{Error, SapResult};
use lazy_static::lazy_static;
use murmur3::murmur3_32;
use sdp::SessionDescription;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::{
    io::Cursor,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{net::UdpSocket, select, spawn, sync::mpsc, time::interval};

pub mod error;

const DEFAULT_PAYLOAD_TYPE: &str = "application/sdp";
const DEFAULT_SAP_PORT: u16 = 9875;
const DEFAULT_MULTICAST_ADDRESS: &str = "239.255.255.255";

lazy_static! {
    static ref HASH_SEED: u32 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("something is wrong with the system clock")
        .as_secs() as u32;
}

#[derive(Debug, Clone)]
pub struct SessionAnnouncement {
    pub deletion: bool,
    pub encrypted: bool,
    pub compressed: bool,
    pub msg_id_hash: u16,
    pub auth_data: Option<String>,
    pub originating_source: IpAddr,
    pub payload_type: Option<String>,
    pub sdp: SessionDescription,
}

impl SessionAnnouncement {
    pub fn new(sdp: SessionDescription) -> SapResult<Self> {
        Ok(Self {
            deletion: false,
            encrypted: false,
            compressed: false,
            msg_id_hash: sdp_hash(&sdp),
            auth_data: None,
            originating_source: sdp.origin.unicast_address.parse()?,
            payload_type: Some(DEFAULT_PAYLOAD_TYPE.to_owned()),
            sdp,
        })
    }
}

pub struct Sap {
    socket: UdpSocket,
    multicast_addr: SocketAddr,
    deletion_announcement: Option<SessionAnnouncement>,
}

impl Sap {
    pub async fn new() -> SapResult<Self> {
        let multicast_addr = SocketAddr::new(
            IpAddr::V4(DEFAULT_MULTICAST_ADDRESS.parse()?),
            DEFAULT_SAP_PORT,
        );
        let socket = create_socket().await?;

        Ok(Sap {
            socket,
            multicast_addr,
            deletion_announcement: None,
        })
    }

    pub async fn discover_sessions(self) -> mpsc::Receiver<SapResult<SessionAnnouncement>> {
        let mut buf = [0; 1024];

        let (tx, rx) = mpsc::channel(10);

        spawn(async move {
            loop {
                match self.socket.recv(&mut buf).await {
                    Ok(len) => {
                        let msg = decode_sap(&buf[..len]);
                        if let Err(e) = tx.send(msg).await {
                            log::error!("Error forwarding SAP message error: {e}");
                            break;
                        }
                    }
                    Err(e) => {
                        if let Err(e) = tx.send(Err(Error::IoError(e))).await {
                            log::error!("Error forwarding SAP message error: {e}");
                        }
                        break;
                    }
                }
            }
        });

        rx
    }

    pub async fn announce_session(&mut self, announcement: SessionAnnouncement) -> SapResult<()> {
        self.delete_session().await?;

        let mut deletion_announcement = announcement.clone();
        deletion_announcement.deletion = true;
        self.deletion_announcement = Some(deletion_announcement);

        let mut interval = interval(Duration::from_secs(5));

        loop {
            // TODO receive other announcements and update delay
            // TODO send announcement in according intervals
            //
            select! {
                _ = interval.tick() => self.send_announcement(&announcement).await?,
            }
        }
    }

    pub async fn delete_session(&mut self) -> SapResult<()> {
        if let Some(deletion_announcement) = self.deletion_announcement.take() {
            log::info!("Deleting active session.");
            let msg = encode_sap(&deletion_announcement);
            self.socket.send_to(&msg, &self.multicast_addr).await?;
        } else {
            log::debug!("No session active, nothing to delete.");
        }

        Ok(())
    }

    async fn send_announcement(&self, announcement: &SessionAnnouncement) -> SapResult<()> {
        log::info!("Broadcasting session description.");
        let msg = encode_sap(announcement);
        self.socket.send_to(&msg, &self.multicast_addr).await?;
        Ok(())
    }
}

pub fn decode_sap(msg: &[u8]) -> SapResult<SessionAnnouncement> {
    let mut min_length = 4;

    if msg.len() < min_length {
        return Err(Error::MalformedPacket(msg.to_owned()));
    }

    let header = msg[0];
    let auth_len = msg[1];
    let msg_id_hash = u16::from_be_bytes([msg[2], msg[3]]);

    let ipv6 = (header & 0b00001000) >> 3 == 1;
    let deletion = (header & 0b00000100) >> 2 == 1;
    let encrypted = (header & 0b00000010) >> 1 == 1;
    let compressed = header & 0b00000001 == 1;

    // TODO implement decryption
    if encrypted {
        return Err(Error::NotImplemented("encryption"));
    }
    // TODO implement decompression
    if compressed {
        return Err(Error::NotImplemented("encryption"));
    }

    if ipv6 {
        min_length += 16;
    } else {
        min_length += 4;
    }

    if msg.len() < min_length {
        return Err(Error::MalformedPacket(msg.to_owned()));
    }

    let originating_source = if ipv6 {
        let bits = u128::from_be_bytes([
            msg[4], msg[5], msg[6], msg[7], msg[8], msg[9], msg[10], msg[11], msg[12], msg[13],
            msg[14], msg[15], msg[16], msg[17], msg[18], msg[19],
        ]);
        IpAddr::V6(Ipv6Addr::from_bits(bits))
    } else {
        let bits = u32::from_be_bytes([msg[4], msg[5], msg[6], msg[7]]);
        IpAddr::V4(Ipv4Addr::from_bits(bits))
    };

    let auth_data_start = min_length;

    min_length += auth_len as usize;

    if msg.len() <= min_length {
        return Err(Error::MalformedPacket(msg.to_owned()));
    }

    let auth_data = if auth_len > 0 {
        Some(String::from_utf8_lossy(&msg[auth_data_start..min_length]).to_string())
    } else {
        None
    };

    let payload = String::from_utf8_lossy(&msg[min_length..]).to_string();
    let split: Vec<&str> = payload.split('\0').collect();

    let payload_type = if split.len() >= 2 {
        Some(split[0].to_owned())
    } else {
        None
    };

    let payload = if split.len() == 1 {
        split[0]
    } else {
        &split[1..].join("\0")
    };

    let sdp = SessionDescription::unmarshal(&mut Cursor::new(payload))?;

    Ok(SessionAnnouncement {
        deletion,
        encrypted,
        compressed,
        msg_id_hash,
        auth_data,
        originating_source,
        payload_type,
        sdp,
    })
}

pub fn encode_sap(msg: &SessionAnnouncement) -> Vec<u8> {
    let v = 1u8;
    let (a, originating_source): (u8, &[u8]) = match msg.originating_source {
        IpAddr::V4(addr) => (0u8, &addr.octets()),
        IpAddr::V6(addr) => (1u8, &addr.octets()),
    };
    let r = 0u8;
    let t = if msg.deletion { 1u8 } else { 0u8 };
    let e = if msg.encrypted { 1u8 } else { 0u8 };
    let c = if msg.compressed { 1u8 } else { 0u8 };
    let header = v << 5 | a << 4 | r << 3 | t << 2 | e << 1 | c;
    let auth_len = msg
        .auth_data
        .as_ref()
        .map(|d| d.as_bytes().len())
        .unwrap_or(0) as u8;
    let msg_id_hash = msg.msg_id_hash.to_be_bytes();

    let mut data = Vec::new();
    data.push(header);
    data.push(auth_len);
    data.extend_from_slice(&msg_id_hash);
    data.extend_from_slice(originating_source);
    if let Some(auth_data) = &msg.auth_data {
        data.extend_from_slice(auth_data.as_bytes());
    }
    if let Some(payload_type) = &msg.payload_type {
        data.extend_from_slice(payload_type.as_bytes());
        data.push(b'\0');
    }
    data.extend_from_slice(msg.sdp.marshal().as_bytes());

    data
}

fn sdp_hash(sdp: &SessionDescription) -> u16 {
    murmur3_32(&mut Cursor::new(sdp.marshal()), *HASH_SEED).unwrap_or(0) as u16
}

async fn create_socket() -> SapResult<UdpSocket> {
    let multicast_addr: Ipv4Addr = DEFAULT_MULTICAST_ADDRESS.parse()?;
    let local_ip = Ipv4Addr::UNSPECIFIED;
    let local_addr = SocketAddr::new(IpAddr::V4(local_ip), DEFAULT_SAP_PORT);

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&SockAddr::from(local_addr))?;
    socket.join_multicast_v4(&multicast_addr, &local_ip)?;

    let tokio_socket = UdpSocket::from_std(socket.into())?;

    Ok(tokio_socket)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn sdp_gets_hashed_correctly() {
        let sdp = SessionDescription::unmarshal(&mut Cursor::new(
            "v=0
o=- 123456 123458 IN IP4 10.0.1.2
s=My sample flow
i=4 channels: c1, c2, c3, c4
t=0 0
a=recvonly
m=audio 5004 RTP/AVP 98
c=IN IP4 239.69.11.44/32
a=rtpmap:98 L24/48000/4
a=ptime:1
a=ts-refclk:ptp=IEEE1588-2008:00-11-22-FF-FE-33-44-55:0
a=mediaclk:direct=0",
        ))
        .unwrap();
        assert!(sdp_hash(&sdp) != 0);
    }

    #[test]
    fn encode_decode_roundtrip_is_successful() {
        let sdp = "v=0
o=- 123456 123458 IN IP4 10.0.1.2
s=My sample flow
i=4 channels: c1, c2, c3, c4
t=0 0
a=recvonly
m=audio 5004 RTP/AVP 98
c=IN IP4 239.69.11.44/32
a=rtpmap:98 L24/48000/4
a=ptime:1
a=ts-refclk:ptp=IEEE1588-2008:00-11-22-FF-FE-33-44-55:0
a=mediaclk:direct=0
";

        let sa = SessionAnnouncement {
            auth_data: None,
            payload_type: None,
            compressed: false,
            deletion: true,
            encrypted: false,
            msg_id_hash: 1234,
            originating_source: "127.0.0.1".parse().unwrap(),
            sdp: SessionDescription::unmarshal(&mut Cursor::new(sdp)).unwrap(),
        };

        let sa_msg = encode_sap(&sa);

        let decoded = decode_sap(&sa_msg).unwrap();

        assert_eq!(sa.auth_data, decoded.auth_data);
        assert_eq!(sa.compressed, decoded.compressed);
        assert_eq!(sa.deletion, decoded.deletion);
        assert_eq!(sa.encrypted, decoded.encrypted);
        assert_eq!(sa.msg_id_hash, decoded.msg_id_hash);
        assert_eq!(sa.originating_source, decoded.originating_source);
        assert_eq!(sa.payload_type, decoded.payload_type);
        assert_eq!(sa.sdp.marshal().replace('\r', ""), sdp);
    }
}
