use miette::{IntoDiagnostic, Result};
use sap_rs::Sap;
use sdp::SessionDescription;
use std::{
    io::{self, Cursor},
    time::Duration,
};
use tosub::SubsystemHandle;
use tracing_subscriber::EnvFilter;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let iface_name = std::env::args()
        .nth(1)
        .expect("specify interface name as first argument");

    tosub::build_root("sap-browser")
        .catch_signals()
        .with_timeout(Duration::from_secs(1))
        .start(|s| run(s, iface_name))
        .await?;

    Ok(())
}

async fn run(subsys: SubsystemHandle, iface_name: String) -> Result<()> {
    let sdp = tokio::fs::read_to_string("./examples/test.sdp")
        .await
        .into_diagnostic()?;

    let (sap, _events) = Sap::new(&subsys, iface_name).await.into_diagnostic()?;

    let sd = SessionDescription::unmarshal(&mut Cursor::new(sdp)).into_diagnostic()?;

    sap.announce_session(sd).await.into_diagnostic()?;

    subsys.shutdown_requested().await;

    Ok(())
}
