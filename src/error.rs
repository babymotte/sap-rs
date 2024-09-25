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

use std::{io, net::AddrParseError};
use thiserror::Error;
use tokio::sync::{mpsc::error::SendError, oneshot::error::RecvError};

#[derive(Error, Debug)]
pub enum Error {
    #[error("network io error: {0}")]
    IoError(#[from] io::Error),
    #[error("address parse error: {0}")]
    AddrParseError(#[from] AddrParseError),
    #[error("malformed session announement packet: {0:?}")]
    MalformedPacket(Vec<u8>),
    #[error("sdp parse error: {0}")]
    SdpParseError(#[from] sdp::Error),
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),
    #[error("internal channel error: {0}")]
    RecvError(#[from] RecvError),
}

impl<T> From<SendError<T>> for Error {
    fn from(_: SendError<T>) -> Self {
        Error::IoError(io::Error::new(
            io::ErrorKind::Other,
            "internal channel error",
        ))
    }
}

pub type SapResult<T> = Result<T, Error>;
