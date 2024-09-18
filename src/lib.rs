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

use error::SapResult;
use lazy_static::lazy_static;
use murmur3::murmur3_32;
use sdp::SessionDescription;
use std::{
    io::Cursor,
    net::{IpAddr, SocketAddr},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{net::UdpSocket, select, time::interval};

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
    deletion: bool,
    encrypted: bool,
    compressed: bool,
    msg_id_hash: u16,
    auth_data: Option<String>,
    originating_source: IpAddr,
    payload_type: Option<String>,
    sdp: SessionDescription,
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
        let socket = UdpSocket::bind(format!("0.0.0.0:{DEFAULT_SAP_PORT}")).await?;
        let multicast_addr: IpAddr = DEFAULT_MULTICAST_ADDRESS.parse()?;
        let socket_addr = SocketAddr::new(multicast_addr, DEFAULT_SAP_PORT);

        Ok(Sap {
            socket,
            multicast_addr: socket_addr,
            deletion_announcement: None,
        })
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

fn encode_sap(msg: &SessionAnnouncement) -> Vec<u8> {
    let v = 1u8;
    let (a, originating_source): (u8, &[u8]) = match msg.originating_source {
        IpAddr::V4(addr) => (0u8, &addr.octets()),
        IpAddr::V6(addr) => (1u8, &addr.octets()),
    };
    let r = 0u8;
    let t = if msg.deletion { 1u8 } else { 0u8 };
    let e = if msg.encrypted { 1u8 } else { 0u8 };
    let c = if msg.compressed { 1u8 } else { 0u8 };
    let header = v << 5 | a << 4 | r << 3 | t << 2 | e << 1 | c << 0;
    let auth_len = msg
        .auth_data
        .as_ref()
        .map(|d| d.as_bytes().len())
        .unwrap_or(0) as u8;
    let msg_id_hash = msg.msg_id_hash.to_le_bytes();

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
}
