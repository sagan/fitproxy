use std::io;
use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;
use tracing::debug;

use crate::outbound::connect_host;

pub async fn handle_direct(
    mut client_stream: TcpStream,
    target_host: &str,
    port: u16,
    egress_mark: Option<u32>,
) -> io::Result<()> {
    debug!("Connecting directly to {}:{}", target_host, port);

    let mut target_stream = connect_host(target_host, port, egress_mark).await?;
    let _ = copy_bidirectional(&mut client_stream, &mut target_stream).await?;
    Ok(())
}
