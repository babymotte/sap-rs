use miette::{IntoDiagnostic, Result};
use sap_rs::{Event, Sap};
use std::io;
use tokio::{select, sync::oneshot};
use tracing_subscriber::EnvFilter;
use worterbuch_client::{connect_with_default_config, topic};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let (wb_disco_tx, mut wb_disco_rx) = oneshot::channel();
    let on_disconnect = async move {
        wb_disco_tx.send(()).ok();
    };
    let (wb, _) = connect_with_default_config(on_disconnect)
        .await
        .into_diagnostic()?;

    wb.set_client_name("SAP browser").await.ok();
    wb.set_grave_goods(&["discovery/sap/#"])
        .await
        .into_diagnostic()?;

    let (_, mut events) = Sap::new().await.into_diagnostic()?;

    loop {
        select! {
            _ = &mut wb_disco_rx => {
                log::warn!("wb connection closed");
                break
            },
            recv = events.recv() => match recv {
                Some(msg) => {
                    match msg {
                        Event::SessionFound(sa) => {
                            let key = topic!("discovery/sap", sa.originating_source.to_string(), sa.msg_id_hash);
                            let sdp = sa.sdp.marshal();
                            log::debug!("SDP {} was announced by {}:\n{}", sa.msg_id_hash, sa.originating_source, sdp);
                            wb.set(key, sdp).await.into_diagnostic()?;
                        },
                        Event::SessionLost(sa) => {
                            let key = topic!("discovery/sap", sa.originating_source.to_string(), sa.msg_id_hash);
                            log::debug!("SDP {} was deleted by {}.", sa.msg_id_hash, sa.originating_source);
                            wb.delete::<String>(key).await.into_diagnostic()?;
                        },
                    }
                },
                None => break,
            }
        }
    }

    Ok(())
}
