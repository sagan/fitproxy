use std::io;
use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;
use tracing::debug;

pub async fn handle_direct(
    mut client_stream: TcpStream,
    domain: &str,
    port: u16,
) -> io::Result<()> {
    let target_addr = format!("{}:{}", domain, port);
    debug!("Connecting directly to {}", target_addr);

    let mut target_stream = TcpStream::connect(&target_addr).await?;
    let _ = copy_bidirectional(&mut client_stream, &mut target_stream).await?;
    Ok(())
}
