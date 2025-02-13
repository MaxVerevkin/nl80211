//! Pretty print host interfaces.

use neli_wifi::AsyncSocket;
use std::error::Error;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut socket = AsyncSocket::connect().await?;

    for interface in socket.get_interfaces_info().await? {
        dbg!(&interface);

        if let Some(index) = interface.index {
            dbg!(socket.get_station_info(index).await?);
            dbg!(socket.get_bss_info(index).await?);
        }

        eprintln!("---");
    }

    Ok(())
}
